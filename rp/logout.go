package rp

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Kolonnade/Portiko/protocol"
	"github.com/Kolonnade/Portiko/rp/session"
	"github.com/Kolonnade/Portiko/internal/verify"
)

// BackchannelLogoutHandler receives OpenID Connect back-channel logout tokens
// (POST, form field logout_token) and ends the sessions they name. Register its
// URL with the accounts service (accountsweb set-logout-uri).
//
// This is how a sign-out at the accounts service reaches this site. The call is
// server to server — no browser, no cookies — so it works the same for a site on
// the accounts service's own domain and for one on an unrelated domain, where a
// browser-based logout would need third-party cookies that browsers block.
//
// The session store must implement session.LogoutStore; if it does not, the
// handler answers 501 so the accounts service logs the site as not notified.
func (c *Client) BackchannelLogoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		store, ok := c.cfg.Sessions.(session.LogoutStore)
		if !ok {
			http.Error(w, "this site's session store cannot end sessions by logout token", http.StatusNotImplemented)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}
		claims, err := c.verifyLogoutToken(r.Context(), r.PostForm.Get("logout_token"))
		if err != nil {
			http.Error(w, "invalid logout token", http.StatusBadRequest)
			return
		}
		if _, err := store.DeleteForLogout(r.Context(), claims.Subject, claims.SessionID); err != nil {
			http.Error(w, "could not end sessions", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// verifyLogoutToken checks a logout token with the same signature, issuer and
// expiry rules as any other token, addressed to this client_id.
//
// An ID token is also addressed to the client_id and signed by the same key, so
// two claims tell them apart: a logout token must carry the back-channel logout
// event and must not carry a nonce. Without both checks, an ID token captured
// from this site could be replayed here to sign its owner out.
func (c *Client) verifyLogoutToken(ctx context.Context, raw string) (*verify.Claims, error) {
	if raw == "" {
		return nil, errors.New("rp: missing logout_token")
	}
	claims, err := verify.Token(ctx, raw, verify.Options{
		Issuer:   c.issuer,
		Audience: c.cfg.ClientID,
		Keys:     c.keys,
		Type:     protocol.TypeLogoutToken,
		Leeway:   30 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	events, _ := claims.Raw[protocol.ClaimEvents].(map[string]any)
	if _, ok := events[protocol.EventBackchannelLogout]; !ok {
		return nil, errors.New("rp: token is not a back-channel logout token")
	}
	if _, ok := claims.Raw[protocol.ClaimNonce]; ok {
		return nil, errors.New("rp: a logout token must not carry a nonce")
	}
	if _, ok := claims.Raw[protocol.ClaimIssuedAt]; !ok {
		return nil, errors.New("rp: logout token has no iat")
	}
	return claims, nil
}
