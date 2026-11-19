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

// emailRequest authenticates an email API call the way passkeyRequest does:
// JSON, from this provider's own origin, naming its account. With reauth set it
// also requires a recent passkey ceremony. A refusal is reported as a failure of
// stage.
func (h *Auth) emailRequest(w http.ResponseWriter, r *http.Request, stage SignInStage, reauth bool) (*account, *emailBody, bool) {
	a, b, reason := h.emailRequestReason(w, r, reauth)
	if reason != "" {
		h.emit(r, stage, OutcomeFail, reason)
		return nil, nil, false
	}
	return a, b, true
}

func (h *Auth) emailRequestReason(w http.ResponseWriter, r *http.Request, reauth bool) (*account, *emailBody, string) {
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
	if reauth && time.Since(a.AuthenticatedAt) > ReauthWindow {
		writeError(w, http.StatusForbidden, &kitprotocol.Error{Code: errReauthRequired,
			Description: "sign in with your passkey again to change your email addresses"})
		return nil, nil, errReauthRequired
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
	a, b, ok := h.emailRequest(w, r, StageEmailAdded, true)
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
	a, b, ok := h.emailRequest(w, r, StageEmailAdded, false)
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
	a, _, ok := h.emailRequest(w, r, StageEmailPrimaryChanged, true)
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
	a, _, ok := h.emailRequest(w, r, StageEmailRemoved, true)
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
	})
}
