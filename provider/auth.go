package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Kolonnade/Portiko/internal/accounts"
	"github.com/Kolonnade/Portiko/internal/config"
	"github.com/Kolonnade/Portiko/internal/keys"
	"github.com/Kolonnade/Portiko/internal/store"
	"github.com/Kolonnade/Portiko/profile"
	kitprotocol "github.com/Kolonnade/Portiko/protocol"
)

// Auth serves the passkey ceremonies, the browser's accounts and signing out.
type Auth struct {
	// policySet: a RegistrationPolicy replaces the invitation code.
	policySet bool
	cfg       *config.Config
	db        *store.DB
	svc       *accounts.Service
	ring      *keys.Ring // signs the logout and event tokens sent to sites
	op        *op.Provider
	profiles  profile.Source
	pages     *Pages
	onEvent   func(context.Context, SignInEvent)
}

// clientIP is the requesting address, with X-Forwarded-For believed only from a
// configured trusted proxy.
func (h *Auth) clientIP(r *http.Request) string { return clientIP(h.cfg.TrustedProxies, r) }

// generic is the only failure a client ever sees from the ceremony endpoints.
//
// Every cause collapses to one response — unknown account, wrong code, expired
// challenge, bad signature. The distinction is exactly what an attacker would
// use to enumerate accounts, and the server logs carry the real step instead.
func generic(w http.ResponseWriter) {
	writeError(w, http.StatusUnauthorized, &kitprotocol.Error{Code: "authentication_failed"})
}

// StartRegistration: POST /accounts/v1/register/start {"email", "bootstrap_code"?}
//
// Always 202, always the same body. Whether the address is new, already
// registered, malformed, or refused for want of the bootstrap code is not
// disclosed. The one exception is an embedder's RegistrationPolicy: when it
// turns a new address away the answer is 403 registration_refused with the
// policy's message in error_description (docs/registration.md).
func (h *Auth) StartRegistration(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email         string `json:"email"`
		BootstrapCode string `json:"bootstrap_code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		h.emit(r, StageEmailSubmitted, OutcomeFail, "bad_request")
	} else {
		h.emit(r, StageEmailSubmitted, OutcomeOK, "")
		err := h.svc.StartRegistration(r.Context(), body.Email, body.BootstrapCode)
		var refused *accounts.RefusedError
		switch {
		case err == nil:
			h.emit(r, StageCodeSent, OutcomeOK, "")
		case errors.As(err, &refused):
			h.emit(r, StageCodeSent, OutcomeFail, ErrRegistrationRefused)
		default:
			h.emit(r, StageCodeSent, OutcomeFail, "send_error")
		}
		if errors.As(err, &refused) {
			// Only an embedder's RegistrationPolicy gets here. Unlike the
			// static modes it says no out loud, so the page can explain.
			writeError(w, http.StatusForbidden, &kitprotocol.Error{
				Code: ErrRegistrationRefused, Description: refused.Message,
			})
			return
		}
		if err != nil {
			slog.ErrorContext(r.Context(), "register start", "err", err)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "code_sent"})
}

// VerifyCode: POST /accounts/v1/register/verify {"email","code"} → creation options.
func (h *Auth) VerifyCode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		generic(w)
		return
	}
	res, err := h.svc.VerifyCode(r.Context(), body.Email, body.Code)
	if err != nil {
		h.emit(r, StageCodeVerified, OutcomeFail, storeReason(err))
		generic(w)
		return
	}
	h.emit(r, StageCodeVerified, OutcomeOK, "")
	h.emit(r, StagePasskeyCreateStarted, OutcomeOK, "")
	writeJSON(w, map[string]any{"purpose": res.Purpose, "creation_options": res.Options})
}

// FinishRegistration: POST /accounts/v1/register/finish[?authRequestID=]
func (h *Auth) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	response, err := protocol.ParseCredentialCreationResponseBody(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		h.emit(r, StagePasskeyCreateDone, OutcomeFail, "parse_error")
		generic(w)
		return
	}
	user, signIn, err := h.svc.FinishRegistration(r.Context(),
		[]byte(response.Response.CollectedClientData.Challenge), response,
		accounts.Caller{IP: h.clientIP(r), UserAgent: r.UserAgent()})
	if err != nil {
		h.emit(r, StagePasskeyCreateDone, OutcomeFail, "verify_failed")
		generic(w)
		return
	}
	h.establishSession(w, r, user, signIn, StagePasskeyCreateDone)
}

// StartLogin: GET /accounts/v1/login/start → assertion options.
func (h *Auth) StartLogin(w http.ResponseWriter, r *http.Request) {
	options, err := h.svc.StartLogin(r.Context(), r.URL.Query().Get("email"))
	if err != nil {
		h.emit(r, StagePasskeySignInStarted, OutcomeFail, "start_failed")
		generic(w)
		return
	}
	h.emit(r, StagePasskeySignInStarted, OutcomeOK, "")
	writeJSON(w, options)
}

// FinishLogin: POST /accounts/v1/login/finish[?authRequestID=]
func (h *Auth) FinishLogin(w http.ResponseWriter, r *http.Request) {
	response, err := protocol.ParseCredentialRequestResponseBody(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		h.emit(r, StagePasskeySignInDone, OutcomeFail, "parse_error")
		generic(w)
		return
	}
	user, signIn, err := h.svc.FinishLogin(r.Context(),
		[]byte(response.Response.CollectedClientData.Challenge), response)
	if errors.Is(err, accounts.ErrUnknownCredential) {
		// The one failure told apart (see accounts.ErrUnknownCredential): the
		// page passes these two fields to signalUnknownCredential.
		h.emit(r, StagePasskeySignInDone, OutcomeFail, "unknown_credential")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":         "unknown_credential",
			"rp_id":         h.cfg.WebAuthnRPID,
			"credential_id": base64.RawURLEncoding.EncodeToString(response.RawID),
		})
		return
	}
	if err != nil {
		h.emit(r, StagePasskeySignInDone, OutcomeFail, "verify_failed")
		generic(w)
		return
	}
	h.establishSession(w, r, user, signIn, StagePasskeySignInDone)
}

// establishSession adds the account that just completed a ceremony to this
// browser, and, when the ceremony was part of a site's sign-in, completes that
// authorization request with it.
//
// stage is the ceremony's finished stage, reported once the outcome is known.
func (h *Auth) establishSession(w http.ResponseWriter, r *http.Request, user *store.User, signIn *accounts.SignIn, stage SignInStage) {
	token, sess, err := h.db.AddSession(r.Context(), browserToken(r), user.ID, signIn.AMR, signIn.RestrictedUntil, r.UserAgent(), h.clientIP(r))
	if errors.Is(err, store.ErrTooManyAccounts) {
		h.emit(r, stage, OutcomeFail, "too_many_accounts")
		writeError(w, http.StatusConflict, &kitprotocol.Error{
			Code:        "too_many_accounts",
			Description: "sign out of an account on this browser before adding another",
		})
		return
	}
	if err != nil {
		h.emit(r, stage, OutcomeFail, "server_error")
		slog.ErrorContext(r.Context(), "adding session", "err", err)
		writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
		return
	}
	SetSSOCookie(w, h.cfg.BasePath(), token, time.Now().Add(store.SessionTTL), !h.cfg.DevInsecure)
	h.emit(r, stage, OutcomeOK, "")

	next := h.cfg.BasePath() + "/u/" + strconv.Itoa(sess.Ordinal) + "/"
	if id := r.URL.Query().Get("authRequestID"); id != "" {
		next = h.continueAuthRequest(r, id, user, sess)
	}
	writeJSON(w, map[string]any{
		"status":   "signed_in",
		"subject":  user.Subject,
		"account":  sess.Ordinal,
		"redirect": next,
	})
}

// continueAuthRequest completes a site's pending sign-in with the account that
// just authenticated, or sends the person back through the handoff when this
// account is not the one the request asked for.
func (h *Auth) continueAuthRequest(r *http.Request, id string, user *store.User, sess *store.Session) string {
	retry := h.cfg.BasePath() + "/login?authRequestID=" + url.QueryEscape(id)
	ar, err := h.db.AuthRequestByID(r.Context(), id)
	if err != nil {
		// A request that ran out while the person was signing in goes back
		// to its site through the handoff, which answers login_required so the
		// site can start again (Login.expired). Only an unknown one ends here.
		if _, err := h.db.ExpiredAuthRequest(r.Context(), id); err == nil {
			return retry
		}
		return h.cfg.BasePath() + "/u/" + strconv.Itoa(sess.Ordinal) + "/"
	}
	if ar.HintSubject != "" && ar.HintSubject != user.Subject {
		h.emitFor(r, id, ar.ClientID, StageRedirected, OutcomeFail, "account_mismatch", "server")
		return retry
	}
	if err := h.db.CompleteAuthRequest(r.Context(), ar.ID, user.ID, sess.SID, sess.AuthenticatedAt, sess.AMR); err != nil {
		h.emitFor(r, id, ar.ClientID, StageRedirected, OutcomeFail, "complete_failed", "server")
		return retry
	}
	h.emitFor(r, id, ar.ClientID, StageRedirected, OutcomeOK, "", "server")
	return callbackURL(h.cfg.Issuer, id)
}

// keepAlive starts the time of the authorization request a sign-in page or
// endpoint names (?authRequestID=) again, so a person still working through
// the ceremony does not lose the site that sent them (store.AuthRequestTTL).
func (h *Auth) keepAlive(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, id := flowOf(r); id != "" {
			if err := h.db.TouchAuthRequest(r.Context(), id); err != nil {
				slog.WarnContext(r.Context(), "auth request: extending", "err", err)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Logout: POST /accounts/v1/logout {"account": n}
//
// With an account, that account signs out of this browser. Without one, every
// account in this browser does. Either way its refresh tokens are revoked and
// each site that held one is told. A form post (the home page's buttons) is
// redirected; a script gets JSON.
func (h *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	token := browserToken(r)
	raw := accountParam(r)
	if token != "" {
		if raw != "" {
			if n, err := strconv.Atoi(raw); err == nil {
				ended, err := h.db.EndSession(r.Context(), token, n)
				switch {
				case err == nil:
					h.notifyEnded(r, ended)
				case !errors.Is(err, store.ErrNotFound):
					slog.ErrorContext(r.Context(), "logout: ending session", "err", err)
				}
			}
		} else {
			ended, err := h.db.EndBrowser(r.Context(), token)
			if err != nil {
				slog.ErrorContext(r.Context(), "logout: ending browser", "err", err)
			}
			for i := range ended {
				h.notifyEnded(r, &ended[i])
			}
		}
	}
	remaining := h.accounts(r)
	if len(remaining) == 0 {
		ClearSSOCookie(w, h.cfg.BasePath(), !h.cfg.DevInsecure)
	}
	if isFormPost(r) {
		to := h.cfg.BasePath() + "/signin"
		if len(remaining) > 0 {
			to = h.cfg.BasePath() + "/"
		}
		http.Redirect(w, r, to, http.StatusSeeOther)
		return
	}
	writeJSON(w, map[string]any{"status": "signed_out", "remaining": len(remaining)})
}

// LogoutAll: POST /accounts/v1/logout/all {"account": n} — that account, in
// every browser, with every refresh token it holds.
func (h *Auth) LogoutAll(w http.ResponseWriter, r *http.Request) {
	a, ok := selectAccount(h.accounts(r), accountParam(r))
	if !ok {
		generic(w)
		return
	}
	clientIDs, err := h.db.EndAllSessions(r.Context(), a.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
		return
	}
	h.notifyLogout(r.Context(), a.User.Subject, "", clientIDs)
	remaining := h.accounts(r)
	if len(remaining) == 0 {
		ClearSSOCookie(w, h.cfg.BasePath(), !h.cfg.DevInsecure)
	}
	writeJSON(w, map[string]any{"status": "signed_out_everywhere", "remaining": len(remaining)})
}

// SetDefault: POST /accounts/v1/default {"account": n}
func (h *Auth) SetDefault(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(accountParam(r))
	if err != nil || h.db.SetDefaultSession(r.Context(), browserToken(r), n) != nil {
		generic(w)
		return
	}
	if isFormPost(r) {
		http.Redirect(w, r, h.cfg.BasePath()+"/u/"+strconv.Itoa(n)+"/", http.StatusSeeOther)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "default": n})
}

func (h *Auth) notifyEnded(r *http.Request, e *store.EndedSession) {
	if u, err := h.db.ByID(r.Context(), e.UserID); err == nil {
		h.notifyLogout(r.Context(), u.Subject, e.SID, e.ClientIDs)
	}
}

// accountParam reads the account number from a form, a JSON body or the query.
func accountParam(r *http.Request) string {
	if isFormPost(r) {
		return r.PostFormValue("account")
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") && r.Body != nil {
		var body struct {
			Account *int `json:"account"`
		}
		if json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<10)).Decode(&body) == nil && body.Account != nil {
			return strconv.Itoa(*body.Account)
		}
		return ""
	}
	return r.URL.Query().Get("account")
}

func isFormPost(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(ct, "multipart/form-data")
}
