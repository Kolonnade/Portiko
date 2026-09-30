package rp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Kolonnade/Portiko/protocol"
	"github.com/Kolonnade/Portiko/rp/session"
	"github.com/Kolonnade/Portiko/internal/verify"
)

// EventsHandler receives Security Event Tokens pushed by the accounts service
// (RFC 8935: POST, Content-Type application/secevent+jwt, the token as the body)
// and applies the ones this site understands. Register its URL with the
// accounts service (accountsweb set-events-uri).
//
// Today that is a profile change, the CAEP token-claims-change event: the new
// name, avatar and updated_at are written to every session of the subject, so
// an open page shows them on its next focus check instead of after a token
// refresh. The call is server to server, so it works the same for a site on
// another domain. The session store must implement session.ProfileStore.
func (c *Client) EventsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		store, ok := c.cfg.Sessions.(session.ProfileStore)
		if !ok {
			http.Error(w, "this site's session store cannot apply profile changes", http.StatusNotImplemented)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/secevent+jwt") {
			http.Error(w, "expected application/secevent+jwt", http.StatusBadRequest)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}
		subject, change, err := c.verifyProfileEvent(r.Context(), strings.TrimSpace(string(raw)))
		if err != nil {
			http.Error(w, "invalid security event token", http.StatusBadRequest)
			return
		}
		if _, err := store.UpdateProfile(r.Context(), subject, change.name, change.avatar, change.version); err != nil {
			http.Error(w, "could not apply the event", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
}

type profileChange struct {
	name, avatar string
	version      int64
}

// verifyProfileEvent checks a pushed event with the same signature, issuer and
// expiry rules as any other token, addressed to this client_id, and extracts
// the profile change it carries.
//
// An ID token and a logout token are signed by the same key for the same
// audience, so the event type decides: this must carry token-claims-change, and
// no nonce. A logout token (a different event) or an ID token (no events, a
// nonce) replayed here is refused.
func (c *Client) verifyProfileEvent(ctx context.Context, raw string) (string, *profileChange, error) {
	if raw == "" {
		return "", nil, errors.New("rp: empty security event token")
	}
	claims, err := verify.Token(ctx, raw, verify.Options{
		Issuer:   c.issuer,
		Audience: c.cfg.ClientID,
		Keys:     c.keys,
		Type:     protocol.TypeEventToken,
		Leeway:   30 * time.Second,
	})
	if err != nil {
		return "", nil, err
	}
	if _, ok := claims.Raw[protocol.ClaimNonce]; ok {
		return "", nil, errors.New("rp: a security event token must not carry a nonce")
	}
	events, _ := claims.Raw[protocol.ClaimEvents].(map[string]any)
	event, ok := events[protocol.EventTokenClaimsChange].(map[string]any)
	if !ok {
		return "", nil, errors.New("rp: not a token-claims-change event")
	}
	changed, _ := event["claims"].(map[string]any)
	version, _ := changed[protocol.ClaimUpdatedAt].(float64)
	if version <= 0 {
		return "", nil, errors.New("rp: profile event has no updated_at")
	}
	name, _ := changed[protocol.ClaimName].(string)
	avatar, _ := changed[protocol.ClaimAvatar].(string)
	return claims.Subject, &profileChange{name: name, avatar: avatar, version: int64(version)}, nil
}
