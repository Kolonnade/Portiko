package provider

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Kolonnade/Portiko/internal/passkey"
	"github.com/Kolonnade/Portiko/internal/store"
	"github.com/Kolonnade/Portiko/profile"
	kitprotocol "github.com/Kolonnade/Portiko/protocol"
)

// Error codes of the passkey endpoints.
const (
	errLastPasskey = "cannot_revoke_last_passkey"
	errNotFound    = "not_found"
)

// passkeyView is one passkey as the API and the page show it: display metadata
// only, never the public key or the raw credential id.
type passkeyView struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Provider   string     `json:"provider"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// providerHint names the passkey provider behind an AAGUID, for people who have
// several passkeys and need to tell them apart. Most platform authenticators
// report no AAGUID on purpose, and an AAGUID outside the short table is not
// worth guessing at, so both read "Unknown".
func providerHint(aaguid []byte) string {
	if name := passkey.AuthenticatorName(aaguid); name != "" {
		return name
	}
	return "Unknown"
}

func viewPasskeys(list []store.ManagedCredential) []passkeyView {
	out := make([]passkeyView, 0, len(list))
	for _, c := range list {
		out = append(out, passkeyView{
			ID: c.ID, Name: c.Name, Provider: providerHint(c.AAGUID),
			CreatedAt: c.CreatedAt.UTC(), LastUsedAt: utcPtr(c.LastUsedAt),
		})
	}
	return out
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// acceptedSignal is what a page hands to
// PublicKeyCredential.signalAllAcceptedCredentials after a revoke, so the
// passkey provider stops offering the credential that was just deleted. The
// Signal API is per user handle, and an account may hold passkeys under more
// than one, so each handle lists the credentials still valid for it — empty for
// a handle whose last credential just went.
type acceptedSignal struct {
	RPID  string               `json:"rp_id"`
	Users []acceptedSignalUser `json:"users"`
}

type acceptedSignalUser struct {
	UserID        string   `json:"user_id"`
	CredentialIDs []string `json:"credential_ids"`
}

func (h *Auth) acceptedSignalFor(r *http.Request, userID int64, revokedHandle []byte) *acceptedSignal {
	remaining, err := h.db.ByUser(r.Context(), userID)
	if err != nil {
		slog.ErrorContext(r.Context(), "passkeys: loading credentials for the signal", "err", err)
		return nil
	}
	enc := base64.RawURLEncoding.EncodeToString
	s := &acceptedSignal{RPID: h.cfg.WebAuthnRPID, Users: []acceptedSignalUser{}}
	index := map[string]int{}
	add := func(handle []byte) int {
		k := enc(handle)
		if i, ok := index[k]; ok {
			return i
		}
		s.Users = append(s.Users, acceptedSignalUser{UserID: k, CredentialIDs: []string{}})
		index[k] = len(s.Users) - 1
		return index[k]
	}
	if revokedHandle != nil {
		add(revokedHandle)
	}
	for _, c := range remaining {
		i := add(c.UserHandle)
		s.Users[i].CredentialIDs = append(s.Users[i].CredentialIDs, enc(c.CredentialID))
	}
	return s
}

// passkeyRequest authenticates a passkey API call and returns the account it
// names. It writes the error itself when it cannot.
//
// A state-changing call must be JSON (a cross-site page cannot send that without
// a CORS preflight) and must come from this provider's own origin, the same two
// locks as the profile and sign-in endpoints; the cookie is SameSite=Lax
// besides. A state-changing call must name its account (400 without one); the
// read-only list may omit it and gets the browser's default account.
func (h *Auth) passkeyRequest(w http.ResponseWriter, r *http.Request, body any) (*account, bool) {
	raw := r.URL.Query().Get("account")
	if body != nil {
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
		var b struct {
			Account *int   `json:"account"`
			Name    string `json:"name"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&b); err != nil {
			writeError(w, http.StatusBadRequest, &kitprotocol.Error{
				Code: kitprotocol.ErrInvalidRequest, Description: "malformed request body"})
			return nil, false
		}
		if b.Account == nil {
			writeError(w, http.StatusBadRequest, &kitprotocol.Error{
				Code: kitprotocol.ErrInvalidRequest, Description: "account is required"})
			return nil, false
		}
		raw = strconv.Itoa(*b.Account)
		if p, ok := body.(*string); ok {
			*p = b.Name
		}
	}
	a, ok := selectAccount(h.accounts(r), raw)
	if !ok {
		writeError(w, http.StatusUnauthorized, &kitprotocol.Error{Code: kitprotocol.ErrLoginRequired})
		return nil, false
	}
	return a, true
}

func passkeyID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		notFound(w)
		return 0, false
	}
	return id, true
}

// notFound is the one answer for a passkey that does not exist and for one that
// belongs to somebody else.
func notFound(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, &kitprotocol.Error{Code: errNotFound, Description: "passkey not found"})
}

// ListPasskeys: GET /accounts/v1/passkeys?account=n
func (h *Auth) ListPasskeys(w http.ResponseWriter, r *http.Request) {
	a, ok := h.passkeyRequest(w, r, nil)
	if !ok {
		return
	}
	list, err := h.db.ListManaged(r.Context(), a.UserID)
	if err != nil {
		slog.ErrorContext(r.Context(), "passkeys: listing", "err", err)
		writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{"account": a.Ordinal, "passkeys": viewPasskeys(list)})
}

// RenamePasskey: POST /accounts/v1/passkeys/{id}/rename {"account", "name"}
//
// The name is Portiko's own label for the credential. WebAuthn has no signal
// that renames one credential — signalCurrentUserDetails names the account's
// user, which the profile page already sends — so nothing is signaled here.
func (h *Auth) RenamePasskey(w http.ResponseWriter, r *http.Request) {
	var name string
	a, ok := h.passkeyRequest(w, r, &name)
	if !ok {
		return
	}
	id, ok := passkeyID(w, r)
	if !ok {
		return
	}
	name, err := profile.NormalizeName(name)
	if err != nil {
		desc := err.Error()
		if errors.Is(err, profile.ErrNameEmpty) {
			desc = "passkey name is required"
		}
		writeError(w, http.StatusBadRequest, &kitprotocol.Error{Code: kitprotocol.ErrInvalidRequest, Description: desc})
		return
	}
	previous, err := h.db.RenameCredential(r.Context(), a.UserID, id, name)
	if errors.Is(err, store.ErrNotFound) {
		notFound(w)
		return
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "passkeys: renaming", "err", err)
		writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
		return
	}
	// Saving the name a passkey already has changes nothing, so it leaves no row.
	if previous != name {
		h.db.Audit(r.Context(), store.AuditEvent{
			UserID: &a.UserID, Action: store.AuditCredentialRenamed,
			IP: h.clientIP(r), UserAgent: r.UserAgent(),
			Detail: map[string]any{"credential_id": id, "from": previous, "to": name},
		})
	}
	h.respondPasskeys(w, r, a, nil)
}

// RevokePasskey: POST /accounts/v1/passkeys/{id}/revoke {"account"}
//
// Refused with 409 when it is the account's last passkey. The response carries
// a "signal" for signalAllAcceptedCredentials so the passkey provider drops the
// credential too.
func (h *Auth) RevokePasskey(w http.ResponseWriter, r *http.Request) {
	a, ok := h.passkeyRequest(w, r, new(string))
	if !ok {
		return
	}
	id, ok := passkeyID(w, r)
	if !ok {
		return
	}
	gone, err := h.db.Revoke(r.Context(), a.UserID, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		notFound(w)
		return
	case errors.Is(err, store.ErrLastCredential):
		writeError(w, http.StatusConflict, &kitprotocol.Error{Code: errLastPasskey,
			Description: "this is your only passkey; add another before removing it, or you could not sign in"})
		return
	case err != nil:
		slog.ErrorContext(r.Context(), "passkeys: revoking", "err", err)
		writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
		return
	}
	h.db.Audit(r.Context(), store.AuditEvent{
		UserID: &a.UserID, Action: store.AuditCredentialRevoked,
		IP: h.clientIP(r), UserAgent: r.UserAgent(),
		Detail: map[string]any{"credential_id": id, "name": gone.Name, "provider": providerHint(gone.AAGUID)},
	})
	h.respondPasskeys(w, r, a, h.acceptedSignalFor(r, a.UserID, gone.UserHandle))
}

// respondPasskeys answers a change with the account's passkeys as they now are.
func (h *Auth) respondPasskeys(w http.ResponseWriter, r *http.Request, a *account, sig *acceptedSignal) {
	list, err := h.db.ListManaged(r.Context(), a.UserID)
	if err != nil {
		slog.ErrorContext(r.Context(), "passkeys: listing", "err", err)
		writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
		return
	}
	out := map[string]any{"account": a.Ordinal, "passkeys": viewPasskeys(list)}
	if sig != nil {
		out["signal"] = sig
	}
	writeJSON(w, out)
}
