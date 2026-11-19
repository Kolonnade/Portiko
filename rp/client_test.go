package rp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Kolonnade/Portiko/protocol"
	"github.com/Kolonnade/Portiko/rp"
	"github.com/Kolonnade/Portiko/rp/session"
)

func TestLoginHandlerForwardsPrompt(t *testing.T) {
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/oauth/authorize",
				"token_endpoint":         issuer + "/oauth/token",
				"jwks_uri":               issuer + "/.well-known/jwks.json",
			})
		case protocol.WellKnownPath:
			_ = json.NewEncoder(w).Encode(protocol.Configuration{
				Protocol: protocol.Name, Issuer: issuer,
				VersionsSupported: []string{protocol.VersionMax.String()},
				VersionMinimum:    protocol.VersionMin.String(),
				VersionPreferred:  protocol.VersionMax.String(),
			})
		case "/.well-known/jwks.json":
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	issuer = srv.URL

	c, err := rp.New(context.Background(), rp.Config{
		Issuer: issuer, ClientID: "site", ClientSecret: "s",
		RedirectURL: "http://site.test/auth/callback", Sessions: session.NewMemoryStore(),
		Insecure: true, CookieKey: bytes.Repeat([]byte("k"), 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := c.LoginHandler()
	for _, tc := range []struct {
		prompt string
		sent   bool
	}{
		{"create", true}, {"login", true}, {"select_account", true},
		{"consent", false}, {"bogus", false},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login?prompt="+tc.prompt, nil))
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil || loc.Path != "/oauth/authorize" {
			t.Fatalf("prompt=%s: status %d, Location %q", tc.prompt, rec.Code, rec.Header().Get("Location"))
		}
		got := loc.Query().Get("prompt")
		if tc.sent && got != tc.prompt {
			t.Errorf("prompt=%s: forwarded %q", tc.prompt, got)
		}
		if !tc.sent && got != "" {
			t.Errorf("prompt=%s: forwarded %q, want nothing", tc.prompt, got)
		}
	}
}

// fakeIssuer is a provider that serves discovery and records end_session calls.
type fakeIssuer struct {
	srv        *httptest.Server
	endStatus  int
	endCalls   int
	endRequest url.Values
}

func newFakeIssuer(t *testing.T, endStatus int) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{endStatus: endStatus}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := f.srv.URL
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/oauth/authorize",
				"token_endpoint":         issuer + "/oauth/token",
				"jwks_uri":               issuer + "/.well-known/jwks.json",
				"end_session_endpoint":   issuer + "/oauth/end_session",
			})
		case protocol.WellKnownPath:
			_ = json.NewEncoder(w).Encode(protocol.Configuration{
				Protocol: protocol.Name, Issuer: issuer,
				VersionsSupported: []string{protocol.VersionMax.String()},
				VersionMinimum:    protocol.VersionMin.String(),
				VersionPreferred:  protocol.VersionMax.String(),
			})
		case "/.well-known/jwks.json":
			_, _ = w.Write([]byte(`{"keys":[]}`))
		case "/oauth/end_session":
			_ = r.ParseForm()
			f.endCalls++
			f.endRequest = r.Form
			if f.endStatus == http.StatusFound {
				http.Redirect(w, r, issuer+"/signed-out", http.StatusFound)
				return
			}
			w.WriteHeader(f.endStatus)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func newEndSessionClient(t *testing.T, f *fakeIssuer) (*rp.Client, *session.MemoryStore) {
	t.Helper()
	store := session.NewMemoryStore()
	c, err := rp.New(context.Background(), rp.Config{
		Issuer: f.srv.URL, ClientID: "site", ClientSecret: "s",
		RedirectURL: "http://site.test/auth/callback", Sessions: store,
		Insecure: true, CookieKey: bytes.Repeat([]byte("k"), 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, store
}

func seedSession(t *testing.T, store *session.MemoryStore, idToken string) *session.Session {
	t.Helper()
	s := &session.Session{
		ID: "sess-1", Subject: "sub", IDToken: idToken,
		AccessExpiry: time.Now().Add(time.Hour), ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := store.Put(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	return s
}

func signOut(h http.Handler, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/auth/signout", nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: session.CookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func clearsCookie(rec *httptest.ResponseRecorder) bool {
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == session.CookieName && ck.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestEndSessionHandler_CallsProviderWithHint(t *testing.T) {
	f := newFakeIssuer(t, http.StatusFound)
	c, store := newEndSessionClient(t, f)
	s := seedSession(t, store, "tok")

	rec := signOut(c.EndSessionHandler("/welcome"), s.ID)
	if f.endCalls != 1 {
		t.Fatalf("end_session called %d times, want 1", f.endCalls)
	}
	if got := f.endRequest.Get("id_token_hint"); got != "tok" {
		t.Errorf("id_token_hint = %q, want tok", got)
	}
	if got := f.endRequest.Get("client_id"); got != "site" {
		t.Errorf("client_id = %q, want site", got)
	}
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/welcome" {
		t.Fatalf("got %d %q, want 302 /welcome", rec.Code, rec.Header().Get("Location"))
	}
	if _, err := store.Get(context.Background(), s.ID); err == nil {
		t.Error("the site session survived signing out")
	}
	if !clearsCookie(rec) {
		t.Error("the session cookie was not cleared")
	}
}

func TestEndSessionHandler_ProviderDownStillSignsOut(t *testing.T) {
	f := newFakeIssuer(t, http.StatusInternalServerError)
	c, store := newEndSessionClient(t, f)
	s := seedSession(t, store, "tok")

	rec := signOut(c.EndSessionHandler("/welcome"), s.ID)
	if f.endCalls != 1 {
		t.Fatalf("end_session called %d times, want 1", f.endCalls)
	}
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/welcome" {
		t.Fatalf("got %d %q, want 302 /welcome", rec.Code, rec.Header().Get("Location"))
	}
	if _, err := store.Get(context.Background(), s.ID); err == nil {
		t.Error("the site session survived a failed provider call")
	}
}

// With no usable site session (an in-memory store emptied by a restart, say),
// sign-out sends the browser to the provider to end its own session there,
// rather than straight back to after with the provider still signed in.
func TestEndSessionHandler_NoSessionGoesToTheProvider(t *testing.T) {
	for _, c := range []struct {
		name, cookie, idToken string
	}{
		{"cookie, empty store", "gone", ""},
		{"no cookie", "", ""},
		{"session without an ID token", "sess-1", "-"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeIssuer(t, http.StatusFound)
			client, store := newEndSessionClient(t, f)
			if c.idToken == "-" {
				seedSession(t, store, "")
			}
			rec := signOut(client.EndSessionHandler("/welcome"), c.cookie)
			if f.endCalls != 0 {
				t.Errorf("end_session called server to server %d times with no ID token", f.endCalls)
			}
			loc, err := url.Parse(rec.Header().Get("Location"))
			if err != nil || rec.Code != http.StatusFound {
				t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
			}
			if got := loc.Scheme + "://" + loc.Host + loc.Path; got != f.srv.URL+"/oauth/end_session" {
				t.Fatalf("redirected to %q, want the provider's end_session_endpoint", got)
			}
			q := loc.Query()
			if q.Get("client_id") != "site" || q.Get("post_logout_redirect_uri") != "http://site.test/welcome" || q.Get("id_token_hint") != "" {
				t.Errorf("end_session query = %v", q)
			}
			if c.cookie != "" && !clearsCookie(rec) {
				t.Error("the session cookie was not cleared")
			}
			if _, err := store.Get(context.Background(), "sess-1"); err == nil {
				t.Error("the site session survived signing out")
			}
		})
	}
}

func TestEndSessionHandler_AfterIsLocal(t *testing.T) {
	f := newFakeIssuer(t, http.StatusFound)
	c, store := newEndSessionClient(t, f)
	s := seedSession(t, store, "tok")

	rec := signOut(c.EndSessionHandler("https://evil.example/"), s.ID)
	if got := rec.Header().Get("Location"); got != "/" {
		t.Fatalf("Location = %q, want /", got)
	}
	rec = signOut(c.EndSessionHandler("/\\evil.example"), "")
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if got := loc.Query().Get("post_logout_redirect_uri"); got != "http://site.test/" {
		t.Errorf("post_logout_redirect_uri = %q, want the site root", got)
	}
}
