package rp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

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
