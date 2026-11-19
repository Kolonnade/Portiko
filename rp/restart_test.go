package rp_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// flowCookieOf returns the sign-in flow cookie a response set.
func flowCookieOf(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "portiko_rp_flow" && c.Value != "" {
			return c
		}
	}
	t.Fatalf("no flow cookie set (status %d)", rec.Code)
	return nil
}

func authorizeRedirect(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusFound || loc.Path != "/oauth/authorize" {
		t.Fatalf("not sent to authorize: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	return loc.Query()
}

func callbackWithError(h http.Handler, flow *http.Cookie, state string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?error=login_required&state="+url.QueryEscape(state), nil)
	req.AddCookie(flow)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// A provider that gave up on a sign-in (login_required) gets it started again
// once, keeping where the person was going; a second one is an ordinary failure.
func TestLoginRequiredRestartsOnce(t *testing.T) {
	c, _ := newEndSessionClient(t, newFakeIssuer(t, http.StatusOK))
	login, callback := c.LoginHandler(), c.CallbackHandler()

	rec := httptest.NewRecorder()
	login.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login?prompt=create&login_hint=a%40example.com&return_to=/invite/abc", nil))
	first := authorizeRedirect(t, rec)
	flow := flowCookieOf(t, rec)
	if flow.MaxAge < int((2 * time.Hour).Seconds()) {
		t.Errorf("flow cookie lasts %ds, shorter than the provider keeps a request", flow.MaxAge)
	}

	rec = callbackWithError(callback, flow, first.Get("state"))
	again := authorizeRedirect(t, rec)
	if again.Get("state") == "" || again.Get("state") == first.Get("state") {
		t.Errorf("restart reused state %q", again.Get("state"))
	}
	if again.Get("prompt") != "" {
		t.Errorf("restart repeated prompt=%s", again.Get("prompt"))
	}
	if again.Get("login_hint") != "a@example.com" {
		t.Errorf("restart dropped login_hint: %q", again.Get("login_hint"))
	}
	flow2 := flowCookieOf(t, rec)

	rec = callbackWithError(callback, flow2, again.Get("state"))
	if loc := rec.Header().Get("Location"); rec.Code == http.StatusFound {
		t.Fatalf("a second login_required restarted again: %q", loc)
	}

	// A wrong state is refused before any restart.
	rec = callbackWithError(callback, flow, "not-the-state")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("wrong state: %d", rec.Code)
	}
}
