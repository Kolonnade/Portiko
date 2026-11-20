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

// The opt-in password credential (PASSWORDS=allow, docs/passwords.md).
//
// Every password endpoint takes JSON from the provider's own origin, the same
// two locks as the account endpoints. A passkey ceremony is bound to the origin
// by the browser; a password is not, so the origin check here is what stops
// another site from signing a browser in to an account of its choosing.

// Error codes of the password endpoints.
const (
	errPasswordsOff      = "passwords_not_enabled"
	errWeakPassword      = "weak_password"
	errLastCredential    = "cannot_remove_last_credential"
	errPasswordNotFound  = "not_found"
	maxPasswordBodyBytes = 4 << 10
)

// passwordBody is every field a password endpoint reads.
type passwordBody struct {
	Account  *int   `json:"account"`
	Email    string `json:"email"`
	Token    string `json:"token"`
	Password string `json:"password"`
}

// readPasswordBody applies the two locks and decodes the body, or writes the
// refusal and returns false.
func (h *Auth) readPasswordBody(w http.ResponseWriter, r *http.Request) (*passwordBody, bool) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, &kitprotocol.Error{
			Code: kitprotocol.ErrInvalidRequest, Description: "expected application/json"})
		return nil, false
	}
	if !sameOrigin(r, h.cfg.Issuer) {
		writeError(w, http.StatusForbidden, &kitprotocol.Error{
			Code: kitprotocol.ErrAccessDenied, Description: "cross-origin request refused"})
		return nil, false
	}
	var b passwordBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPasswordBodyBytes)).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, &kitprotocol.Error{
			Code: kitprotocol.ErrInvalidRequest, Description: "malformed request body"})
		return nil, false
	}
	return &b, true
}

func passwordsOff(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, &kitprotocol.Error{Code: errPasswordsOff,
		Description: "this deployment does not use passwords"})
}

func weakPassword(w http.ResponseWriter, err *accounts.WeakPasswordError) {
	writeError(w, http.StatusBadRequest, &kitprotocol.Error{Code: errWeakPassword, Description: err.Message})
}

// RegisterPassword: POST /accounts/v1/register/password[?authRequestID=] {"token", "password"}
//
// The other way to finish register/verify: token is the password_token it
// answered with, and instead of creating a passkey the account gets this
// password. A new address becomes an account; an address that has one is
// recovery, which sets (or replaces) the account's password under the recovery
// hold. The answer is the one register/finish gives.
//
// A password the policy refuses is 400 weak_password, with the reason, and the
// token stays usable. Any other failure is the generic 401.
func (h *Auth) RegisterPassword(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.PasswordsAllowed() {
		passwordsOff(w)
		return
	}
	b, ok := h.readPasswordBody(w, r)
	if !ok {
		h.emit(r, StagePasswordSet, OutcomeFail, "bad_request")
		return
	}
	user, signIn, err := h.svc.FinishPasswordEnrollment(r.Context(), b.Token, b.Password, h.caller(r))
	var weak *accounts.WeakPasswordError
	switch {
	case errors.As(err, &weak):
		h.emit(r, StagePasswordSet, OutcomeFail, errWeakPassword)
		weakPassword(w, weak)
		return
	case err != nil:
		h.emit(r, StagePasswordSet, OutcomeFail, "verify_failed")
		generic(w)
		return
	}
	h.establishSession(w, r, user, signIn, StagePasswordSet)
}

// LoginPassword: POST /accounts/v1/login/password[?authRequestID=] {"email", "password"}
//
// Signs in with any verified address on the account and its password. Every
// failure is the generic 401 (docs/opinions.md), including an account waiting
// out its per-account backoff. The answer is the one login/finish gives, and
// the session's amr is ["pwd"].
func (h *Auth) LoginPassword(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.PasswordsAllowed() {
		passwordsOff(w)
		return
	}
	b, ok := h.readPasswordBody(w, r)
	if !ok {
		h.emit(r, StagePasswordSignInDone, OutcomeFail, "bad_request")
		return
	}
	user, signIn, err := h.svc.PasswordLogin(r.Context(), b.Email, b.Password)
	if err != nil {
		h.emit(r, StagePasswordSignInDone, OutcomeFail, "verify_failed")
		generic(w)
		return
	}
	h.establishSession(w, r, user, signIn, StagePasswordSignInDone)
}

// passwordView is the account's password as the API and the page show it:
// when it was set and used, never anything derived from the password itself.
type passwordView struct {
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// passwordState is what GET /accounts/v1/password answers, and what each
// change answers with afterwards.
func (h *Auth) passwordState(r *http.Request, a *account) (map[string]any, error) {
	var view *passwordView
	p, err := h.db.PasswordOf(r.Context(), a.UserID)
	switch {
	case err == nil:
		view = &passwordView{CreatedAt: p.CreatedAt.UTC(), UpdatedAt: p.UpdatedAt.UTC(), LastUsedAt: utcPtr(p.LastUsedAt)}
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}
	return map[string]any{
		"account": a.Ordinal, "allowed": h.cfg.PasswordsAllowed(), "password": view,
		"reauth_until": reauthUntil(&a.Session), "held_until": heldUntil(&a.Session),
	}, nil
}

func (h *Auth) respondPassword(w http.ResponseWriter, r *http.Request, a *account) {
	out, err := h.passwordState(r, a)
	if err != nil {
		slog.ErrorContext(r.Context(), "password: loading", "err", err)
		writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, out)
}

// GetPassword: GET /accounts/v1/password?account=n
//
// {"account", "allowed", "password": null | {"created_at", "updated_at",
// "last_used_at"}, "reauth_until", "held_until"}. allowed says whether this
// deployment lets a password be set; an account may still hold one after it
// stopped, and may remove it.
func (h *Auth) GetPassword(w http.ResponseWriter, r *http.Request) {
	a, ok := selectAccount(h.accounts(r), r.URL.Query().Get("account"))
	if !ok {
		writeError(w, http.StatusUnauthorized, &kitprotocol.Error{Code: kitprotocol.ErrLoginRequired})
		return
	}
	h.respondPassword(w, r, a)
}

// accountFor resolves the account a state-changing password call names.
func (h *Auth) accountFor(w http.ResponseWriter, r *http.Request, b *passwordBody) (*account, bool) {
	if b.Account == nil {
		writeError(w, http.StatusBadRequest, &kitprotocol.Error{
			Code: kitprotocol.ErrInvalidRequest, Description: "account is required"})
		return nil, false
	}
	a, ok := selectAccount(h.accounts(r), strconv.Itoa(*b.Account))
	if !ok {
		writeError(w, http.StatusUnauthorized, &kitprotocol.Error{Code: kitprotocol.ErrLoginRequired})
		return nil, false
	}
	return a, true
}

// SetPassword: POST /accounts/v1/password {"account", "password"}
//
// Adds a password to the account, or replaces the one it has. Adding needs a
// sign-in within ReauthWindow, as adding an address does; replacing takes the
// old password away, so it is held like removing one (guardHeld). A password
// set by a session in its recovery hold carries the same hold.
func (h *Auth) SetPassword(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.PasswordsAllowed() {
		passwordsOff(w)
		return
	}
	b, ok := h.readPasswordBody(w, r)
	if !ok {
		return
	}
	a, ok := h.accountFor(w, r, b)
	if !ok {
		return
	}
	g := guardReauth
	if _, err := h.db.PasswordOf(r.Context(), a.UserID); err == nil {
		g = guardHeld
	}
	if refuse(w, a, g) != "" {
		return
	}
	_, err := h.svc.SetPassword(r.Context(), a.UserID, b.Password, heldUntil(&a.Session), h.caller(r))
	var weak *accounts.WeakPasswordError
	switch {
	case errors.As(err, &weak):
		weakPassword(w, weak)
		return
	case err != nil:
		slog.ErrorContext(r.Context(), "password: setting", "err", err)
		writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
		return
	}
	h.respondPassword(w, r, a)
}

// RemovePassword: POST /accounts/v1/password/remove {"account"}
//
// Takes the password off the account, whether or not passwords are still
// allowed. Held like revoking a passkey (guardHeld). 404 not_found when the
// account has none, and 409 cannot_remove_last_credential when it has no
// passkey: the account would have no way to sign in.
func (h *Auth) RemovePassword(w http.ResponseWriter, r *http.Request) {
	b, ok := h.readPasswordBody(w, r)
	if !ok {
		return
	}
	a, ok := h.accountFor(w, r, b)
	if !ok {
		return
	}
	if refuse(w, a, guardHeld) != "" {
		return
	}
	err := h.svc.RemovePassword(r.Context(), a.UserID, h.caller(r))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, &kitprotocol.Error{Code: errPasswordNotFound, Description: "this account has no password"})
		return
	case errors.Is(err, store.ErrLastCredential):
		writeError(w, http.StatusConflict, &kitprotocol.Error{Code: errLastCredential,
			Description: "the password is the only way to sign in to this account; add a passkey before removing it"})
		return
	case err != nil:
		slog.ErrorContext(r.Context(), "password: removing", "err", err)
		writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
		return
	}
	h.respondPassword(w, r, a)
}
