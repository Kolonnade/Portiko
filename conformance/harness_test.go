//go:build conformance

package conformance_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Kolonnade/Portiko/conformance"
)

const (
	redirectURI = "https://localhost.emobix.co.uk:8443/test/a/portiko/callback"
	clientID    = "conformance-1"
	secret      = "test-secret-0123456789abcdef"
)

// testDatabaseURL is the provider tests' database, in a schema of its own so the
// two packages can run at once.
func testDatabaseURL(t *testing.T) string {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		base = "postgres://localhost:5432/portiko_test?sslmode=disable"
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Skipf("test database unavailable (%v); createdb portiko_test", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `DROP SCHEMA IF EXISTS conformance CASCADE; CREATE SCHEMA conformance`); err != nil {
		t.Fatalf("resetting the conformance schema: %v", err)
	}
	t.Cleanup(func() {
		if c, err := pgx.Connect(ctx, base); err == nil {
			_, _ = c.Exec(ctx, `DROP SCHEMA IF EXISTS conformance CASCADE`)
			c.Close(ctx)
		}
	})
	u, _ := url.Parse(base)
	q := u.Query()
	q.Set("search_path", "conformance")
	u.RawQuery = q.Encode()
	return u.String()
}

// suiteBrowser is what the suite's headless browser does: follow redirects
// with a cookie jar, and stop at the suite's own callback.
type suiteBrowser struct {
	t      *testing.T
	client *http.Client
	issuer string
}

func newHarness(t *testing.T) (*conformance.Harness, *suiteBrowser) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	// The RP ID must be a name, not an address, so the issuer says localhost.
	_, port, _ := strings.Cut(srv.Listener.Addr().String(), ":")
	issuer := "https://localhost:" + port

	h, err := conformance.New(context.Background(), conformance.Config{
		Issuer:       issuer,
		DatabaseURL:  testDatabaseURL(t),
		RedirectURIs: []string{redirectURI},
		Clients:      []conformance.Client{{ID: clientID, Secret: secret}, {ID: "conformance-2", Secret: secret + "-2"}},
	})
	if err != nil {
		t.Fatalf("harness: %v", err)
	}
	srv.Config.Handler = h
	srv.StartTLS()
	t.Cleanup(func() { srv.Close(); h.Close() })

	jar, _ := cookiejar.New(nil)
	b := &suiteBrowser{t: t, issuer: issuer, client: &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
		// The suite does not verify the provider's certificate either.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), redirectURI) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}}
	return h, b
}

// authorize starts an authorization request and returns where the provider
// finally sent the browser.
func (b *suiteBrowser) authorize(extra url.Values) *url.URL {
	b.t.Helper()
	q := url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {"openid email profile"}, "state": {"st"}, "nonce": {"nn"},
	}
	for k, v := range extra {
		q[k] = v
	}
	resp, err := b.client.Get(b.issuer + "/oauth/authorize?" + q.Encode())
	if err != nil {
		b.t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		b.t.Fatalf("authorize ended at %s with %d, not at the callback", resp.Request.URL, resp.StatusCode)
	}
	return loc
}

func pkce(verifier string) url.Values {
	sum := sha256.Sum256([]byte(verifier))
	return url.Values{
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
}

// redeem exchanges a code, authenticating with HTTP Basic as most of the Basic
// OP plan's modules do.
func (b *suiteBrowser) redeem(code, verifier string) map[string]any {
	b.t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	req, _ := http.NewRequest(http.MethodPost, b.issuer+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("token: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK {
		b.t.Fatalf("token: %d %v", resp.StatusCode, out)
	}
	return out
}

func (b *suiteBrowser) userinfo(accessToken string) map[string]any {
	b.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, b.issuer+"/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("userinfo: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func claims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// The suite's browser, which has no passkey, is signed in by the harness with
// the real ceremony and ends at the suite's callback with a code that redeems.
// A second request reuses the session; prompt=login signs in again.
func TestHarnessSignsInForTheSuitesBrowser(t *testing.T) {
	h, b := newHarness(t)

	// Discovery is the provider's own.
	resp, err := b.client.Get(b.issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var disc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&disc)
	resp.Body.Close()
	if disc["issuer"] != b.issuer {
		t.Fatalf("discovery issuer = %v, want %s", disc["issuer"], b.issuer)
	}

	loc := b.authorize(pkce("verifier-one-0123456789-0123456789-0123456789"))
	code := loc.Query().Get("code")
	if code == "" || loc.Query().Get("state") != "st" {
		t.Fatalf("callback = %s", loc)
	}
	if h.SignIns() != 1 {
		t.Fatalf("sign-ins = %d, want 1", h.SignIns())
	}
	tok := b.redeem(code, "verifier-one-0123456789-0123456789-0123456789")
	idt, _ := tok["id_token"].(string)
	c := claims(t, idt)
	if c["iss"] != b.issuer || !audContains(c["aud"], clientID) || c["nonce"] != "nn" {
		t.Fatalf("id_token claims: %v", c)
	}
	if info := b.userinfo(tok["access_token"].(string)); info["sub"] != c["sub"] {
		t.Fatalf("userinfo: %v", info)
	}
	firstAuth, _ := c["auth_time"].(float64)

	// Signed in already: no ceremony.
	if loc := b.authorize(pkce("verifier-two-0123456789-0123456789-0123456789")); loc.Query().Get("code") == "" {
		t.Fatalf("second authorization: %s", loc)
	}
	if h.SignIns() != 1 {
		t.Fatalf("an existing session signed in again: %d", h.SignIns())
	}

	// prompt=login asks for a fresh ceremony, and auth_time moves.
	time.Sleep(1100 * time.Millisecond)
	loc = b.authorize(merge(pkce("verifier-three-0123456789-0123456789-01234567"), url.Values{"prompt": {"login"}}))
	if loc.Query().Get("code") == "" {
		t.Fatalf("prompt=login: %s", loc)
	}
	if h.SignIns() != 2 {
		t.Fatalf("prompt=login sign-ins = %d, want 2", h.SignIns())
	}
	c = claims(t, b.redeem(loc.Query().Get("code"), "verifier-three-0123456789-0123456789-01234567")["id_token"].(string))
	if at, _ := c["auth_time"].(float64); at <= firstAuth {
		t.Fatalf("auth_time %v did not move past %v after prompt=login", at, firstAuth)
	}
}

// The harness adds no way in: an unregistered redirect URI is still refused
// with an error page, not a redirect.
func TestHarnessLeavesTheProviderAlone(t *testing.T) {
	_, b := newHarness(t)
	q := merge(pkce("verifier-0123456789-0123456789-0123456789-0123"), url.Values{
		"client_id": {clientID}, "redirect_uri": {"https://evil.example/cb"}, "response_type": {"code"}, "scope": {"openid"},
	})
	resp, err := b.client.Get(b.issuer + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || resp.Request.URL.Host != strings.TrimPrefix(b.issuer, "https://") {
		t.Fatalf("unregistered redirect URI: %d at %s", resp.StatusCode, resp.Request.URL)
	}
	if _, err := resp.Location(); !errors.Is(err, http.ErrNoLocation) {
		t.Fatalf("unregistered redirect URI was redirected")
	}
}

func merge(a, b url.Values) url.Values {
	for k, v := range b {
		a[k] = v
	}
	return a
}

func audContains(aud any, id string) bool {
	if s, ok := aud.(string); ok {
		return s == id
	}
	list, _ := aud.([]any)
	for _, a := range list {
		if a == id {
			return true
		}
	}
	return false
}
