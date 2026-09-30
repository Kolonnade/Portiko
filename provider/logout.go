package provider

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Kolonnade/Portiko/internal/store"
)

// logoutTimeout bounds how long a sign-out waits on the sites. A site that is
// down must not leave the user waiting; it misses the notice, and its session
// still ends at its next token refresh because the refresh token was revoked
// with the SSO session.
const logoutTimeout = 3 * time.Second

// clientHTTP never follows redirects: a logout or events endpoint must not
// redirect, and following one would deliver the token somewhere else.
var clientHTTP = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// notifyLogout sends an OpenID Connect back-channel logout token to every client
// in clientIDs that registered a logout URI, in parallel, and waits for them up
// to logoutTimeout.
//
// This is how signing out here reaches the sites. It is a server-to-server POST,
// so it needs no cookies and works the same for a site on another registrable
// domain as for a subdomain. The browser-based alternative, front-channel logout,
// loads each site in a hidden iframe and depends on third-party cookies, which
// browsers block.
//
// sid names the SSO session that ended, so a site ends only the sessions that
// came from this browser; an empty sid means every session for the subject.
func (h *Auth) notifyLogout(ctx context.Context, subject, sid string, clientIDs []string) {
	clients, err := h.db.LogoutRecipients(ctx, clientIDs)
	if err != nil {
		slog.ErrorContext(ctx, "logout: loading recipients", "err", err)
		return
	}
	// Detached from the request so a browser that navigates away mid-sign-out
	// does not cancel the notices.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), logoutTimeout)
	defer cancel()

	var wg sync.WaitGroup
	for _, c := range clients {
		wg.Add(1)
		go func(c store.Client) {
			defer wg.Done()
			log := slog.With("client_id", c.ClientID)
			token, err := h.ring.SignLogout(h.cfg.Issuer, c.ClientID, subject, sid)
			if err != nil {
				log.ErrorContext(ctx, "logout: signing logout token", "err", err)
				return
			}
			h.deliver(ctx, log, "logout", c.BackchannelLogoutURI,
				"application/x-www-form-urlencoded", url.Values{"logout_token": {token}}.Encode())
		}(c)
	}
	wg.Wait()
}

// deliver POSTs body to a client's registered URI and logs the outcome under
// what ("logout", "profile event"). Outside development it refuses any URI that
// is not https, since the body is a bearer-style credential for that client.
func (h *Auth) deliver(ctx context.Context, log *slog.Logger, what, uri, contentType, body string) {
	u, err := url.Parse(uri)
	if err != nil || (u.Scheme != "https" && !(h.cfg.DevInsecure && u.Scheme == "http")) {
		log.WarnContext(ctx, what+": refusing a non-https client URI", "uri", uri)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(body))
	if err != nil {
		log.ErrorContext(ctx, what+": building request", "err", err)
		return
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := clientHTTP.Do(req)
	if err != nil {
		log.WarnContext(ctx, what+": notifying client", "err", err)
		return
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusNoContent:
		log.InfoContext(ctx, what+": client notified")
	default:
		log.WarnContext(ctx, what+": client refused", "status", resp.StatusCode)
	}
}
