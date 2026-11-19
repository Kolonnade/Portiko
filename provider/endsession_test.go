package provider_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/Kolonnade/Portiko/internal/store"
)

func (h *harness) sessionCount(email string) int {
	h.t.Helper()
	var n int
	if err := h.db.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM sso_sessions s JOIN identifiers i ON i.user_id = s.user_id WHERE i.value = $1`,
		email).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// #0090: a site that lost its own session sends the browser to end_session
// with only client_id. The provider ends the sessions in that browser that
// signed in to that site, and only those.
func TestEndSessionWithoutHintEndsThisBrowsersSessionsForTheSite(t *testing.T) {
	h := newHarness(t)
	h.register("shared@example.com")
	s := h.newSite("groups", func(c *store.Client) {
		c.PostLogoutRedirectURIs = []string{c.Audience + "/welcome"}
	})
	resp, err := h.client.Get(s.url + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// A second account in the same browser that never used the site.
	h.register("bystander@example.com")

	c := *h.client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	end := func(clientID string) *http.Response {
		q := url.Values{"client_id": {clientID}, "post_logout_redirect_uri": {s.url + "/welcome"}}
		r, err := c.Get(h.srv.URL + "/oauth/end_session?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r
	}

	// Another site's request ends nothing here.
	h.newSite("other")
	end("other")
	if h.sessionCount("shared@example.com") != 1 {
		t.Fatal("a request for a site the account never used signed it out")
	}

	r := end("groups")
	if loc := r.Header.Get("Location"); r.StatusCode != http.StatusFound || loc != s.url+"/welcome" {
		t.Fatalf("end_session: %d %q", r.StatusCode, loc)
	}
	if h.sessionCount("shared@example.com") != 0 {
		t.Error("the account that signed in to the site is still signed in at the provider")
	}
	if h.sessionCount("bystander@example.com") != 1 {
		t.Error("an account that never used the site was signed out")
	}
	var live int
	_ = h.db.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM refresh_tokens WHERE client_id = 'groups' AND revoked_at IS NULL`).Scan(&live)
	if live != 0 {
		t.Errorf("%d refresh tokens for the site survived", live)
	}

	// With no provider cookie at all there is nothing to end, and it still
	// returns to the site.
	bare := &http.Client{CheckRedirect: c.CheckRedirect}
	q := url.Values{"client_id": {"groups"}, "post_logout_redirect_uri": {s.url + "/welcome"}}
	r2, err := bare.Get(h.srv.URL + "/oauth/end_session?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusFound || r2.Header.Get("Location") != s.url+"/welcome" {
		t.Errorf("no cookie: %d %q", r2.StatusCode, r2.Header.Get("Location"))
	}
	if h.sessionCount("bystander@example.com") != 1 {
		t.Error("a request with no cookie signed someone out")
	}
}
