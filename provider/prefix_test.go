package provider_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/jackc/pgx/v5"

	"github.com/Kolonnade/Portiko/internal/config"
	"github.com/Kolonnade/Portiko/provider"
	"github.com/Kolonnade/Portiko/rp"
	"github.com/Kolonnade/Portiko/rp/session"
)

func TestBasePathComesFromTheIssuer(t *testing.T) {
	for issuer, want := range map[string]string{
		"https://accounts.example.com":  "",
		"https://accounts.example.com/": "",
		"https://go.example.com/id":     "/id",
		"https://go.example.com/id/":    "/id",
		"https://go.example.com/a/b":    "/a/b",
		"http://127.0.0.1:8080/sso":     "/sso",
	} {
		if got := (&config.Config{Issuer: issuer}).BasePath(); got != want {
			t.Errorf("BasePath(%q) = %q, want %q", issuer, got, want)
		}
	}
}

// One ServeMux serves a host application and the provider under /id. The host
// keeps its own "/", "/health" and "/u/{key}", and a person signs in to the
// host through the provider on the same origin, with a passkey, using the rp
// library with a RedirectURL under the host's own paths.
func TestProviderEmbeddedUnderAPathPrefix(t *testing.T) {
	resetSchema(t)
	ctx := context.Background()

	srv := httptest.NewUnstartedServer(nil)
	origin := "http://" + srv.Listener.Addr().String()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	t.Setenv("ISSUER", origin+"/id")
	t.Setenv("DATABASE_URL", testDatabaseURL())
	t.Setenv("WEBAUTHN_RP_ID", "localhost")
	t.Setenv("WEBAUTHN_RP_ORIGINS", origin)
	t.Setenv("DEV_INSECURE", "true")
	t.Setenv("CRYPTO_KEY", hex.EncodeToString(key))
	t.Setenv("SERVICE_NAME", "Embedded")
	cfg, err := provider.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := pgx.Connect(ctx, cfg.DatabaseURL); err == nil {
		_, err := conn.Exec(ctx, `TRUNCATE users, identifiers, passkey_credentials, webauthn_challenges,
			pending_registrations, sso_sessions, browsers, oauth_clients, auth_requests, refresh_tokens,
			auth_audit, signing_keys, rate_counters RESTART IDENTITY CASCADE`)
		conn.Close(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	mail := &fakeMailer{}
	p, err := provider.New(ctx, cfg, provider.Options{Mailer: mail})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	redirect := origin + "/auth/callback"
	if err := p.RegisterClient(ctx, provider.Client{
		ID: "host", Secret: "s", Audience: origin, RedirectURIs: []string{redirect}, FirstParty: true,
	}); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "host home") })
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "host health") })
	mux.HandleFunc("GET /u/{key}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "host link "+r.PathValue("key"))
	})
	mux.Handle("/id/", p.Handler())
	srv.Config.Handler = mux
	srv.Start()
	t.Cleanup(srv.Close)

	// The relying party lives on the same origin as the issuer.
	kit, err := rp.New(ctx, rp.Config{
		Issuer: origin + "/id", ClientID: "host", ClientSecret: "s", RedirectURL: redirect,
		Sessions: session.NewMemoryStore(), Insecure: true, CookieKey: bytes.Repeat([]byte("k"), 32),
	})
	if err != nil {
		t.Fatalf("rp against an issuer with a path: %v", err)
	}
	mux.Handle("GET /auth/login", kit.LoginHandler())
	mux.Handle("GET /auth/callback", kit.CallbackHandler())
	mux.Handle("GET /me", kit.RequireUserAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := rp.SessionFrom(r.Context())
		_, _ = io.WriteString(w, "signed in as "+sess.Subject)
	})))

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	body := func(resp *http.Response, err error) (int, string) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// The host's routes are the host's.
	for path, want := range map[string]string{"/": "host home", "/health": "host health", "/u/abc": "host link abc"} {
		if code, b := body(client.Get(origin + path)); code != 200 || b != want {
			t.Errorf("GET %s = %d %q, want %q", path, code, b, want)
		}
	}
	// The provider answers only under its prefix.
	if code, _ := body(client.Get(origin + "/signin")); code != http.StatusNotFound {
		t.Errorf("GET /signin = %d, want the host's 404", code)
	}
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if resp, err := noFollow.Get(origin + "/id"); err != nil || resp.StatusCode/100 != 3 || resp.Header.Get("Location") != "/id/" {
		t.Errorf("GET /id: %v %v", err, resp)
	} else {
		resp.Body.Close()
	}

	// Discovery names the prefix everywhere.
	_, disc := body(client.Get(origin + "/id/.well-known/openid-configuration"))
	var doc map[string]any
	if err := json.Unmarshal([]byte(disc), &doc); err != nil {
		t.Fatalf("discovery: %v: %s", err, disc)
	}
	for _, k := range []string{"issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri", "end_session_endpoint"} {
		v, _ := doc[k].(string)
		if !strings.HasPrefix(v, origin+"/id") {
			t.Errorf("discovery %s = %q, want it under %s/id", k, v, origin)
		}
	}
	if code, b := body(client.Get(doc["jwks_uri"].(string))); code != 200 || !strings.Contains(b, `"keys"`) {
		t.Errorf("jwks: %d %s", code, b)
	}
	for _, wk := range []string{"/id/.well-known/portiko-configuration", "/id/.well-known/eureka-accounts-configuration"} {
		if code, b := body(client.Get(origin + wk)); code != 200 || !strings.Contains(b, origin+"/id") {
			t.Errorf("%s: %d %s", wk, code, b)
		}
	}

	// A signed-out visit to the host ends at the provider's sign-in page, which
	// sends its API calls and links back under the prefix.
	resp, err := client.Get(origin + "/auth/login?return_to=/me")
	if err != nil {
		t.Fatal(err)
	}
	signin := resp.Request.URL
	_, page := body(resp, nil)
	if signin.Path != "/id/signin" || signin.Query().Get("authRequestID") == "" {
		t.Fatalf("sign-in ended at %s", signin)
	}
	for _, want := range []string{"/id/accounts/v1/login/start", "/id/accounts/v1/register/finish", "/id/login?authRequestID="} {
		if !strings.Contains(strings.ReplaceAll(page, `\/`, "/"), want) {
			t.Errorf("sign-in page lacks %s", want)
		}
	}
	authID := signin.Query().Get("authRequestID")

	// Register a passkey, completing the site's request.
	post := func(path string, body []byte) *http.Response {
		resp, err := client.Post(origin+path, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	email := "embedded@example.com"
	j, _ := json.Marshal(map[string]string{"email": email})
	if r := post("/id/accounts/v1/register/start", j); r.StatusCode != http.StatusAccepted {
		t.Fatalf("register/start: %d", r.StatusCode)
	}
	vj, _ := json.Marshal(map[string]string{"email": email, "code": codeFor(t, p, email)})
	r := post("/id/accounts/v1/register/verify", vj)
	var verified struct {
		CreationOptions json.RawMessage `json:"creation_options"`
	}
	_ = json.NewDecoder(r.Body).Decode(&verified)
	r.Body.Close()
	options, err := virtualwebauthn.ParseAttestationOptions(string(verified.CreationOptions))
	if err != nil {
		t.Fatal(err)
	}
	vrp := virtualwebauthn.RelyingParty{Name: "Embedded", ID: "localhost", Origin: origin}
	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{BackupEligible: true, BackupState: true})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	att := virtualwebauthn.CreateAttestationResponse(vrp, authenticator, cred, *options)
	fin := post("/id/accounts/v1/register/finish?authRequestID="+authID, []byte(att))
	var out struct {
		Redirect string `json:"redirect"`
	}
	_ = json.NewDecoder(fin.Body).Decode(&out)
	fin.Body.Close()
	if fin.StatusCode != 200 || !strings.HasPrefix(out.Redirect, origin+"/id/oauth/authorize/callback") {
		t.Fatalf("register/finish: %d redirect %q", fin.StatusCode, out.Redirect)
	}

	// The cookie is the provider's alone: limited to the prefix.
	var sso *http.Cookie
	for _, c := range fin.Cookies() {
		if c.Name == provider.SSOCookieName {
			sso = c
		}
	}
	if sso == nil || sso.Path != "/id" {
		t.Fatalf("sso cookie = %+v, want Path /id", sso)
	}

	// Following the redirect completes the host's sign-in on the host's callback.
	resp, err = client.Get(out.Redirect)
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Request.URL.Path; got != "/me" {
		t.Fatalf("sign-in ended at %s, want the host's /me", resp.Request.URL)
	}
	if code, b := body(resp, nil); code != 200 || !strings.HasPrefix(b, "signed in as ") {
		t.Fatalf("host /me: %d %q", code, b)
	}
	// The browser holds the provider's cookie for /id and sends none to the host.
	hasSSO := func(path string) bool {
		u, _ := url.Parse(origin + path)
		for _, c := range jar.Cookies(u) {
			if c.Name == provider.SSOCookieName {
				return true
			}
		}
		return false
	}
	if hasSSO("/") || hasSSO("/me") || !hasSSO("/id/") {
		t.Errorf("cookie scope: sent to / = %v, /me = %v, /id/ = %v", hasSSO("/"), hasSSO("/me"), hasSSO("/id/"))
	}
	if code, b := body(client.Get(origin + "/health")); code != 200 || b != "host health" {
		t.Errorf("host /health after sign-in: %d %q", code, b)
	}
	// With the browser signed in, the provider's pages and redirects hold the prefix.
	resp, err = client.Get(origin + "/id/")
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Request.URL.Path; got != "/id/u/0/" {
		t.Errorf("GET /id/ ended at %s, want /id/u/0/", got)
	}
	_, home := body(resp, nil)
	for _, want := range []string{`href="/id/u/0/profile"`, `action="/id/accounts/v1/logout"`, "/id/signin?add=1"} {
		if !strings.Contains(home, want) {
			t.Errorf("home page lacks %s", want)
		}
	}
	// A form-post sign-out returns to the prefixed sign-in page and clears the cookie.
	jarNoFollow := &http.Client{Jar: jar, CheckRedirect: noFollow.CheckRedirect}
	resp, err = jarNoFollow.Post(origin+"/id/accounts/v1/logout", "application/x-www-form-urlencoded", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "/id/signin" {
		t.Errorf("sign-out redirected to %q, want /id/signin", loc)
	}
	var cleared *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == provider.SSOCookieName {
			cleared = c
		}
	}
	if cleared == nil || cleared.MaxAge >= 0 || cleared.Path != "/id" {
		t.Errorf("sign-out cookie = %+v, want a clearing cookie (MaxAge<0) at Path=/id", cleared)
	}
	if hasSSO("/id/") {
		t.Error("the browser still holds the cookie after sign-out")
	}

	// Sign in again with the same passkey, through the host and rp.
	authenticator.AddCredential(cred)
	resp, err = client.Get(origin + "/auth/login?return_to=/me")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	authID = resp.Request.URL.Query().Get("authRequestID")
	if resp.Request.URL.Path != "/id/signin" || authID == "" {
		t.Fatalf("second sign-in ended at %s", resp.Request.URL)
	}
	_, startBody := body(client.Get(origin + "/id/accounts/v1/login/start"))
	aopts, err := virtualwebauthn.ParseAssertionOptions(startBody)
	if err != nil {
		t.Fatalf("login/start: %v: %s", err, startBody)
	}
	found := authenticator.FindAllowedCredential(*aopts)
	if found == nil {
		found = &authenticator.Credentials[0]
	}
	assertion := virtualwebauthn.CreateAssertionResponse(vrp, authenticator, *found, *aopts)
	lf := post("/id/accounts/v1/login/finish?authRequestID="+authID, []byte(assertion))
	out.Redirect = ""
	_ = json.NewDecoder(lf.Body).Decode(&out)
	lf.Body.Close()
	if lf.StatusCode != 200 || !strings.HasPrefix(out.Redirect, origin+"/id/oauth/authorize/callback") {
		t.Fatalf("login/finish: %d redirect %q", lf.StatusCode, out.Redirect)
	}
	resp, err = client.Get(out.Redirect)
	if err != nil {
		t.Fatal(err)
	}
	if code, b := body(resp, nil); resp.Request.URL.Path != "/me" || code != 200 || !strings.HasPrefix(b, "signed in as ") {
		t.Fatalf("passkey sign-in: %s %d %q", resp.Request.URL, code, b)
	}
	if !hasSSO("/id/") || hasSSO("/") {
		t.Error("cookie scope after the second sign-in")
	}
}

// Mounted at the root of a server, as the portiko command does, the handler
// answers only the prefix on a segment boundary and never redirects out of it.
func TestPrefixedHandlerMountedAtTheRoot(t *testing.T) {
	resetSchema(t)
	ctx := context.Background()
	srv := httptest.NewUnstartedServer(nil)
	origin := "http://" + srv.Listener.Addr().String()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	t.Setenv("ISSUER", origin+"/id")
	t.Setenv("DATABASE_URL", testDatabaseURL())
	t.Setenv("WEBAUTHN_RP_ID", "localhost")
	t.Setenv("WEBAUTHN_RP_ORIGINS", origin)
	t.Setenv("DEV_INSECURE", "true")
	t.Setenv("CRYPTO_KEY", hex.EncodeToString(key))
	cfg, err := provider.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := pgx.Connect(ctx, cfg.DatabaseURL); err == nil {
		_, err := conn.Exec(ctx, `TRUNCATE users, identifiers, passkey_credentials, webauthn_challenges,
			pending_registrations, sso_sessions, browsers, oauth_clients, auth_requests, refresh_tokens,
			auth_audit, signing_keys, rate_counters RESTART IDENTITY CASCADE`)
		conn.Close(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	p, err := provider.New(ctx, cfg, provider.Options{Mailer: &fakeMailer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	srv.Config.Handler = p.Handler()
	srv.Start()
	t.Cleanup(srv.Close)

	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, tc := range []struct {
		path     string
		code     int
		location string
	}{
		{"/idx", 404, ""}, {"/idx/foo", 404, ""}, {"/idhealth", 404, ""}, {"/health", 404, ""},
		{"/signin", 404, ""}, {"/id%2Fsignin", 404, ""},
		// Cleaning must never climb out of the prefix.
		{"/id/..", 404, ""}, {"/id/../x", 404, ""}, {"/id/..%2Fx", 404, ""}, {"/id/%2E%2E/x", 404, ""},
		{"/id/health", 200, ""}, {"/id/signin", 200, ""},
		{"/id//signin", 308, "/id/signin"}, {"/id/./signin", 308, "/id/signin"},
		{"/id/x/../signin", 308, "/id/signin"},
		{"/id", 308, "/id/"}, {"/id?x=1", 308, "/id/?x=1"},
	} {
		resp, err := c.Get(origin + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.code || resp.Header.Get("Location") != tc.location {
			t.Errorf("GET %s = %d Location %q, want %d %q", tc.path, resp.StatusCode, resp.Header.Get("Location"), tc.code, tc.location)
		}
	}
}

func codeFor(t *testing.T, p *provider.Provider, email string) string {
	t.Helper()
	var code string
	if err := p.DB().Pool().QueryRow(context.Background(),
		`SELECT code FROM pending_registrations WHERE email = $1 ORDER BY id DESC LIMIT 1`, email).Scan(&code); err != nil {
		t.Fatal(err)
	}
	return code
}
