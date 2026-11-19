package provider_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// #0091: return_to must be a path on the provider. A browser reads "/\host" and
// "/<tab>/host" as "//host", which is another site, so a link on the accounts
// domain could send a signed-in person anywhere.
func TestSignInReturnToStaysOnTheProvider(t *testing.T) {
	h := newHarness(t)
	c := *h.client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	hostile := []string{`/\evil.example`, `/%5Cevil.example`, `/\/evil.example`, `/%09/evil.example`, `https://evil.example`, `//evil.example`}

	// Signed out: the page renders, and the value its script redirects to after
	// sign-in must not be the hostile one.
	for _, v := range hostile {
		resp, err := c.Get(h.srv.URL + "/signin?return_to=" + escapeKeepingPercents(v))
		if err != nil {
			t.Fatal(err)
		}
		body := bodyString(t, resp)
		if !strings.Contains(body, `const RETURN_TO = "";`) {
			t.Errorf("signed out, return_to=%s: the page kept it", v)
		}
	}

	// Signed in: the page redirects at once, and only to the provider.
	h.register("rt@example.com")
	for _, v := range hostile {
		resp, err := c.Get(h.srv.URL + "/signin?return_to=" + escapeKeepingPercents(v))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || loc != "/" {
			t.Errorf("signed in, return_to=%s: %d Location %q, want 302 /", v, resp.StatusCode, loc)
		}
	}
	resp, err := c.Get(h.srv.URL + "/signin?return_to=/profile")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "/profile" {
		t.Errorf("a local path was not kept: %q", loc)
	}
}

// escapeKeepingPercents query-escapes v, except that an existing %XX stays as
// written, so "/%5Cevil" reaches the handler decoded as "/\evil".
func escapeKeepingPercents(v string) string {
	if strings.Contains(v, "%") {
		return v
	}
	return url.QueryEscape(v)
}
