package provider

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Kolonnade/Portiko/internal/accounts"
	"github.com/Kolonnade/Portiko/internal/store"
	kitprotocol "github.com/Kolonnade/Portiko/protocol"
)

// ReauthWindow is how recently an account must have completed a passkey
// ceremony in this browser to add an address, remove one or change the primary.
//
// A session cookie alone is not enough for these. Each one decides which
// inboxes can recover the account, so a borrowed laptop or a stolen cookie that
// could do them would be a way to keep the account for good. Signing in again as
// the same account resets the clock.
const ReauthWindow = 10 * time.Minute

// Error codes of the email endpoints.
const (
	errReauthRequired = "reauthentication_required"
	errRecoveryHold   = "recovery_hold"
	errEmailLimit     = "email_limit_reached"
	errPrimaryEmail   = "cannot_remove_primary_email"
	errInvalidEmail   = "invalid_email"
)

// emailView is one address as the API and the page show it.
type emailView struct {
	ID         int64     `json:"id"`
	Email      string    `json:"email"`
	Primary    bool      `json:"primary"`
	VerifiedAt time.Time `json:"verified_at"`
}

func viewEmails(list []store.Email) []emailView {
	out := make([]emailView, 0, len(list))
	for _, e := range list {
		out = append(out, emailView{ID: e.ID, Email: e.Address, Primary: e.Primary, VerifiedAt: e.VerifiedAt.UTC()})
	}
	return out
}

// emailBody is every field an email endpoint reads.
type emailBody struct {
	Account *int   `json:"account"`
	Email   string `json:"email"`
	Code    string `json:"code"`
}

// guard is how much an account change asks of the session making it.
type guard int

const (
	guardSession guard = iota // the session cookie is enough
	guardReauth               // a passkey ceremony within ReauthWindow
	guardHeld                 // guardReauth, and not with a passkey in its recovery hold
)

// refuse writes the refusal and returns its reason when the session behind a
// may not make a change that needs g, or returns "".
//
// guardHeld covers the changes that take a way in away from the account:
// changing the primary address, removing an address and revoking a passkey. A
// passkey enrolled through recovery cannot make them until
// accounts.RecoveryHold has passed (see there for why).
func refuse(w http.ResponseWriter, a *account, g guard) string {
	if g >= guardReauth && time.Since(a.AuthenticatedAt) > ReauthWindow {
		writeError(w, http.StatusForbidden, &kitprotocol.Error{Code: errReauthRequired,
			Description: "sign in with your passkey again to make this change"})
		return errReauthRequired
	}
	if g >= guardHeld && heldUntil(&a.Session) != nil {
		writeError(w, http.StatusForbidden, &kitprotocol.Error{Code: errRecoveryHold,
			Description: "this passkey was added by recovering the account, so for a week it cannot remove addresses, " +
				"change the primary address or remove passkeys; sign in with a passkey you had before to do it now"})
		return errRecoveryHold
	}
	return ""
}

// heldUntil is when the session's recovery hold ends, or nil when it has none.
func heldUntil(a *store.Session) *time.Time {
	if a.RestrictedUntil == nil || !time.Now().Before(*a.RestrictedUntil) {
		return nil
	}
	u := a.RestrictedUntil.UTC()
	return &u
}

// emailRequest authenticates an email API call the way passkeyRequest does:
// JSON, from this provider's own origin, naming its account, and then applies g.
// A refusal is reported as a failure of stage.
func (h *Auth) emailRequest(w http.ResponseWriter, r *http.Request, stage SignInStage, g guard) (*account, *emailBody, bool) {
	a, b, reason := h.emailRequestReason(w, r, g)
	if reason != "" {
		h.emit(r, stage, OutcomeFail, reason)
		return nil, nil, false
	}
	return a, b, true
}

func (h *Auth) emailRequestReason(w http.ResponseWriter, r *http.Request, g guard) (*account, *emailBody, string) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, &kitprotocol.Error{
			Code: kitprotocol.ErrInvalidRequest, Description: "expected application/json"})
		return nil, nil, "bad_request"
	}
	if !sameOrigin(r, h.cfg.Issuer) {
		writeError(w, http.StatusForbidden, &kitprotocol.Error{
			Code: kitprotocol.ErrAccessDenied, Description: "cross-origin request refused"})
		return nil, nil, "cross_origin"
	}
	var b emailBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, &kitprotocol.Error{
			Code: kitprotocol.ErrInvalidRequest, Description: "malformed request body"})
		return nil, nil, "bad_request"
	}
	if b.Account == nil {
		writeError(w, http.StatusBadRequest, &kitprotocol.Error{
			Code: kitprotocol.ErrInvalidRequest, Description: "account is required"})
		return nil, nil, "bad_request"
	}
	a, ok := selectAccount(h.accounts(r), strconv.Itoa(*b.Account))
	if !ok {
		writeError(w, http.StatusUnauthorized, &kitprotocol.Error{Code: kitprotocol.ErrLoginRequired})
		return nil, nil, "login_required"
	}
	if reason := refuse(w, a, g); reason != "" {
		return nil, nil, reason
	}
	return a, &b, ""
}

func (h *Auth) caller(r *http.Request) accounts.Caller {
	return accounts.Caller{IP: h.clientIP(r), UserAgent: r.UserAgent()}
}

// reauthUntil is when the account's recent ceremony stops counting, or nil when
// it already has.
func reauthUntil(a *store.Session) *time.Time {
	until := a.AuthenticatedAt.Add(ReauthWindow).UTC()
	if time.Now().After(until) {
		return nil
	}
	return &until
}

// ListEmails: GET /accounts/v1/emails?account=n
func (h *Auth) ListEmails(w http.ResponseWriter, r *http.Request) {
	a, ok := selectAccount(h.accounts(r), r.URL.Query().Get("account"))
	if !ok {
		writeError(w, http.StatusUnauthorized, &kitprotocol.Error{Code: kitprotocol.ErrLoginRequired})
		return
	}
	h.respondEmails(w, r, a)
}

// AddEmail: POST /accounts/v1/emails/add {"account","email"} — sends a code to
// the address. Always 202 for an address that is not refused outright: one
// already on an account is sent nothing, and the answer is the same.
func (h *Auth) AddEmail(w http.ResponseWriter, r *http.Request) {
	a, b, ok := h.emailRequest(w, r, StageEmailAdded, guardReauth)
	if !ok {
		return
	}
	err := h.svc.StartAddEmail(r.Context(), a.UserID, b.Email)
	switch {
	case errors.Is(err, accounts.ErrInvalidEmail):
		h.emit(r, StageEmailAdded, OutcomeFail, errInvalidEmail)
		writeError(w, http.StatusBadRequest, &kitprotocol.Error{Code: errInvalidEmail,
			Description: "enter an email address"})
		return
	case errors.Is(err, accounts.ErrEmailLimit):
		h.emit(r, StageEmailAdded, OutcomeFail, errEmailLimit)
		h.limitReached(w)
		return
	case err != nil:
		h.emit(r, StageEmailAdded, OutcomeFail, "server_error")
		slog.ErrorContext(r.Context(), "emails: starting an addition", "err", err)
		writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "code_sent", "account": a.Ordinal})
}

// VerifyEmail: POST /accounts/v1/emails/verify {"account","email","code"} —
// adds the address. A wrong code and an address taken by any account get the
// same 401 authentication_failed.
func (h *Auth) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	a, b, ok := h.emailRequest(w, r, StageEmailAdded, guardSession)
	if !ok {
		return
	}
	_, err := h.svc.VerifyAddEmail(r.Context(), a.UserID, b.Email, b.Code, h.caller(r))
	switch {
	case errors.Is(err, accounts.ErrEmailLimit):
		h.emit(r, StageEmailAdded, OutcomeFail, errEmailLimit)
		h.limitReached(w)
		return
	case err != nil:
		h.emit(r, StageEmailAdded, OutcomeFail, storeReason(err))
		generic(w)
		return
	}
	h.emit(r, StageEmailAdded, OutcomeOK, "")
	h.respondEmails(w, r, a)
}

// MakePrimaryEmail: POST /accounts/v1/emails/{id}/primary {"account"}
func (h *Auth) MakePrimaryEmail(w http.ResponseWriter, r *http.Request) {
	a, _, ok := h.emailRequest(w, r, StageEmailPrimaryChanged, guardHeld)
	if !ok {
		return
	}
	id, ok := emailID(w, r)
	if !ok {
		return
	}
	err := h.svc.MakePrimary(r.Context(), a.UserID, id, h.caller(r))
	switch {
	case errors.Is(err, accounts.ErrEmailNotFound):
		emailNotFound(w)
		return
	case err != nil:
		h.emit(r, StageEmailPrimaryChanged, OutcomeFail, "server_error")
		slog.ErrorContext(r.Context(), "emails: changing the primary", "err", err)
		writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
		return
	}
	h.emit(r, StageEmailPrimaryChanged, OutcomeOK, "")
	h.respondEmails(w, r, a)
}

// RemoveEmail: POST /accounts/v1/emails/{id}/remove {"account"}
func (h *Auth) RemoveEmail(w http.ResponseWriter, r *http.Request) {
	a, _, ok := h.emailRequest(w, r, StageEmailRemoved, guardHeld)
	if !ok {
		return
	}
	id, ok := emailID(w, r)
	if !ok {
		return
	}
	err := h.svc.RemoveEmail(r.Context(), a.UserID, id, h.caller(r))
	switch {
	case errors.Is(err, accounts.ErrEmailNotFound):
		emailNotFound(w)
		return
	case errors.Is(err, accounts.ErrPrimaryEmail):
		h.emit(r, StageEmailRemoved, OutcomeFail, errPrimaryEmail)
		writeError(w, http.StatusConflict, &kitprotocol.Error{Code: errPrimaryEmail,
			Description: "this is your primary address; make another address primary before removing it"})
		return
	case err != nil:
		h.emit(r, StageEmailRemoved, OutcomeFail, "server_error")
		slog.ErrorContext(r.Context(), "emails: removing", "err", err)
		writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
		return
	}
	h.emit(r, StageEmailRemoved, OutcomeOK, "")
	h.respondEmails(w, r, a)
}

func (h *Auth) limitReached(w http.ResponseWriter) {
	writeError(w, http.StatusConflict, &kitprotocol.Error{Code: errEmailLimit,
		Description: "your account has as many email addresses as it can hold; remove one first"})
}

func emailID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		emailNotFound(w)
		return 0, false
	}
	return id, true
}

// emailNotFound is the one answer for an address id that does not exist and for
// one on somebody else's account.
func emailNotFound(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, &kitprotocol.Error{Code: errNotFound, Description: "email address not found"})
}

// respondEmails answers with the account's addresses as they now are.
func (h *Auth) respondEmails(w http.ResponseWriter, r *http.Request, a *account) {
	list, err := h.db.Emails(r.Context(), a.UserID)
	if err != nil {
		slog.ErrorContext(r.Context(), "emails: listing", "err", err)
		writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{
		"account":      a.Ordinal,
		"emails":       viewEmails(list),
		"max":          h.cfg.EmailLimit(),
		"reauth_until": reauthUntil(&a.Session),
		"held_until":   heldUntil(&a.Session),
	})
}
