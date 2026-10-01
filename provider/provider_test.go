package provider_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/jackc/pgx/v5"

	"github.com/Kolonnade/Portiko/internal/mailer"
	"github.com/Kolonnade/Portiko/internal/store"
	"github.com/Kolonnade/Portiko/migrations"
	"github.com/Kolonnade/Portiko/provider"
	"github.com/Kolonnade/Portiko/rp"
	"github.com/Kolonnade/Portiko/rp/session"
)

func testDatabaseURL() string {
	if v := os.Getenv("TEST_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://localhost:5432/portiko_test?sslmode=disable"
}

var (
	schemaOnce sync.Once
	schemaErr  error
)

// resetSchema applies every migration to an empty schema, once per test run.
// Tests skip, rather than fail, when there is no database to run against.
func resetSchema(t *testing.T) {
	t.Helper()
	schemaOnce.Do(func() {
		ctx := context.Background()
		conn, err := pgx.Connect(ctx, testDatabaseURL())
		if err != nil {
			schemaErr = err
			return
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"); err != nil {
			schemaErr = err
			return
		}
		ups, err := migrations.Up()
		if err != nil {
			schemaErr = err
			return
		}
		for _, sql := range ups {
			if _, err := conn.Exec(ctx, sql); err != nil {
				schemaErr = err
				return
			}
		}
	})
	if schemaErr != nil {
		t.Skipf("test database unavailable (%v); createdb portiko_test", schemaErr)
	}
}

type harness struct {
	t          *testing.T
	srv        *httptest.Server
	db         *store.DB
	client     *http.Client
	mail       *fakeMailer
	rp         virtualwebauthn.RelyingParty
	auth       virtualwebauthn.Authenticator
	tokenCalls atomic.Int32
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	resetSchema(t)

	srv := httptest.NewUnstartedServer(nil)
	origin := "http://" + srv.Listener.Addr().String()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	t.Setenv("ISSUER", origin)
	t.Setenv("DATABASE_URL", testDatabaseURL())
	t.Setenv("WEBAUTHN_RP_ID", "localhost")
	t.Setenv("WEBAUTHN_RP_ORIGINS", origin)
	t.Setenv("SERVICE_NAME", "Test Accounts")
	t.Setenv("DEV_INSECURE", "true")
	t.Setenv("CRYPTO_KEY", hex.EncodeToString(key))

	cfg, err := provider.LoadConfig()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ctx := context.Background()
	if pre, err := store.Open(ctx, cfg.DatabaseURL); err == nil {
		_, err := pre.Pool().Exec(ctx, `TRUNCATE users, identifiers, passkey_credentials, webauthn_challenges,
			pending_registrations, sso_sessions, browsers, oauth_clients, auth_requests, refresh_tokens,
			auth_audit, signing_keys RESTART IDENTITY CASCADE`)
		pre.Close()
		if err != nil {
			t.Fatalf("truncate: %v", err)
		}
	}
	mail := &fakeMailer{}
	p, err := provider.New(ctx, cfg, provider.Options{Mailer: mail})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	h := &harness{t: t, srv: srv, db: p.DB(), mail: mail}
	handler := p.Handler()
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			h.tokenCalls.Add(1)
		}
		handler.ServeHTTP(w, r)
	})
	srv.Start()
	t.Cleanup(func() { srv.Close(); p.Close() })

	jar, _ := cookiejar.New(nil)
	h.client = &http.Client{Jar: jar, Timeout: 10 * time.Second}
	h.rp = virtualwebauthn.RelyingParty{Name: "Test Accounts", ID: "localhost", Origin: origin}
	// Backup Eligible and Backup State both set: an iCloud Keychain-style synced
	// passkey, the case that enrolled and then failed every login in ShortLinks.
	h.auth = virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		BackupEligible: true, BackupState: true,
	})
	return h
}

// fakeMailer records what the provider asked to be sent instead of sending it.
//
// Recording rather than silently discarding: "no notice was sent" and "a notice
// was sent to the wrong address" look identical to a mailer that drops
// everything, and the second is the bug this exists to catch.
type fakeMailer struct {
	mu    sync.Mutex
	codes []string
	sent  []sentNotice
}

type sentNotice struct {
	to     string
	notice mailer.PasskeyNotice
}

func (m *fakeMailer) SendCode(to, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes = append(m.codes, to)
	return nil
}

func (m *fakeMailer) SendPasskeyAdded(to string, n mailer.PasskeyNotice) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, sentNotice{to: to, notice: n})
	return nil
}

func (m *fakeMailer) notices() []sentNotice {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]sentNotice(nil), m.sent...)
}

// auditRows returns the audit trail's rows for one action, oldest first.
func (h *harness) auditRows(action string) []auditRow {
	h.t.Helper()
	rows, err := h.db.Pool().Query(context.Background(),
		`SELECT COALESCE(ip::text, ''), COALESCE(user_agent, ''), COALESCE(detail::text, '')
		   FROM auth_audit WHERE action = $1 ORDER BY id`, action)
	if err != nil {
		h.t.Fatalf("reading the audit trail: %v", err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.ip, &r.userAgent, &r.detail); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

type auditRow struct{ ip, userAgent, detail string }

func (h *harness) post(path string, body any) *http.Response {
	h.t.Helper()
	blob, _ := json.Marshal(body)
	resp, err := h.client.Post(h.srv.URL+path, "application/json", bytes.NewReader(blob))
	if err != nil {
		h.t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func (h *harness) get(path string) *http.Response {
	h.t.Helper()
	resp, err := h.client.Get(h.srv.URL + path)
	if err != nil {
		h.t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func bodyString(t *testing.T, r *http.Response) string {
	t.Helper()
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

func (h *harness) latestCode(email string) string {
	h.t.Helper()
	var code string
	if err := h.db.Pool().QueryRow(context.Background(),
		`SELECT code FROM pending_registrations WHERE email = $1 ORDER BY id DESC LIMIT 1`,
		store.NormalizeEmail(email)).Scan(&code); err != nil {
		h.t.Fatalf("reading the pending code: %v", err)
	}
	return code
}

// register enrolls a new account and signs it in on the harness's browser. It
// returns the account number the browser gave it.
func (h *harness) register(email string) int {
	h.t.Helper()
	if resp := h.post("/accounts/v1/register/start", map[string]string{"email": email}); resp.StatusCode != http.StatusAccepted {
		h.t.Fatalf("register/start: %s", bodyString(h.t, resp))
	}
	resp := h.post("/accounts/v1/register/verify", map[string]string{"email": email, "code": h.latestCode(email)})
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("register/verify: %d %s", resp.StatusCode, bodyString(h.t, resp))
	}
	var verified struct {
		CreationOptions json.RawMessage `json:"creation_options"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&verified)
	resp.Body.Close()

	options, err := virtualwebauthn.ParseAttestationOptions(string(verified.CreationOptions))
	if err != nil {
		h.t.Fatalf("parsing attestation options: %v", err)
	}
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	attestation := virtualwebauthn.CreateAttestationResponse(h.rp, h.auth, credential, *options)
	fin, err := h.client.Post(h.srv.URL+"/accounts/v1/register/finish", "application/json", strings.NewReader(attestation))
	if err != nil {
		h.t.Fatalf("register/finish: %v", err)
	}
	if fin.StatusCode != http.StatusOK {
		h.t.Fatalf("register/finish: %d %s", fin.StatusCode, bodyString(h.t, fin))
	}
	var out struct {
		Account int `json:"account"`
	}
	_ = json.NewDecoder(fin.Body).Decode(&out)
	fin.Body.Close()
	h.auth.AddCredential(credential)
	return out.Account
}

func (h *harness) login(email string) *http.Response {
	h.t.Helper()
	path := "/accounts/v1/login/start"
	if email != "" {
		path += "?email=" + url.QueryEscape(email)
	}
	resp := h.get(path)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	options, err := virtualwebauthn.ParseAssertionOptions(string(raw))
	if err != nil {
		h.t.Fatalf("parsing assertion options: %v", err)
	}
	credential := h.auth.FindAllowedCredential(*options)
	if credential == nil {
		credential = &h.auth.Credentials[0]
	}
	assertion := virtualwebauthn.CreateAssertionResponse(h.rp, h.auth, *credential, *options)
	fin, err := h.client.Post(h.srv.URL+"/accounts/v1/login/finish", "application/json", strings.NewReader(assertion))
	if err != nil {
		h.t.Fatalf("login/finish: %v", err)
	}
	return fin
}

func (h *harness) subjectOf(email string) string {
	h.t.Helper()
	u, err := h.db.ByIdentifier(context.Background(), "email", email)
	if err != nil {
		h.t.Fatalf("subject of %s: %v", email, err)
	}
	return u.Subject
}

// ------------------------------------------------------------------ sites

type site struct {
	url      string
	sessions *session.MemoryStore
	secret   string
	clientID string
}

// newSite starts a real Portiko relying party registered with the provider.
func (h *harness) newSite(clientID string, edit ...func(*store.Client)) *site {
	h.t.Helper()
	ctx := context.Background()
	srv := httptest.NewUnstartedServer(nil)
	u := "http://" + srv.Listener.Addr().String()
	c := store.Client{
		ClientID: clientID, Audience: u, DisplayName: clientID,
		RedirectURIs: []string{u + "/auth/callback"}, TrustTier: "first_party",
		AllowedScopes: []string{"openid", "profile", "offline_access"},
	}
	for _, e := range edit {
		e(&c)
	}
	s := &site{url: u, sessions: session.NewMemoryStore(), secret: "s", clientID: clientID}
	if err := h.db.UpsertClient(ctx, c, s.secret); err != nil {
		h.t.Fatal(err)
	}
	kit, err := rp.New(ctx, rp.Config{
		Issuer: h.srv.URL, ClientID: clientID, ClientSecret: s.secret,
		RedirectURL: u + "/auth/callback", Sessions: s.sessions,
		Scopes: []string{"profile"}, Insecure: true, CookieKey: bytes.Repeat([]byte("k"), 32),
	})
	if err != nil {
		h.t.Fatalf("relying party: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /auth/login", kit.LoginHandler())
	mux.Handle("GET /auth/callback", kit.CallbackHandler())
	mux.Handle("POST /auth/backchannel-logout", kit.BackchannelLogoutHandler())
	mux.Handle("POST /auth/events", kit.EventsHandler())
	mux.Handle("GET /api/me", kit.RequireUserAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := rp.SessionFrom(r.Context())
		_, _ = io.WriteString(w, sess.Subject)
	})))
	mux.Handle("GET /{$}", kit.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := rp.SessionFrom(r.Context())
		_, _ = io.WriteString(w, sess.Name+"|"+sess.Avatar)
	})))
	srv.Config.Handler = mux
	srv.Start()
	h.t.Cleanup(srv.Close)
	return s
}

// session returns the site's session for the harness's browser.
func (h *harness) siteSession(s *site) *session.Session {
	h.t.Helper()
	u, _ := url.Parse(s.url)
	for _, ck := range h.client.Jar.Cookies(u) {
		if ck.Name == session.CookieName {
			sess, err := s.sessions.Get(context.Background(), ck.Value)
			if err != nil {
				h.t.Fatalf("site session: %v", err)
			}
			return sess
		}
	}
	h.t.Fatal("the site set no session cookie")
	return nil
}

// ssoCookie returns the browser cookie the provider set on the harness's client.
func (h *harness) ssoCookie() string {
	h.t.Helper()
	u, _ := url.Parse(h.srv.URL)
	for _, ck := range h.client.Jar.Cookies(u) {
		if ck.Name == provider.SSOCookieName {
			return ck.Value
		}
	}
	h.t.Fatal("the provider set no browser cookie")
	return ""
}

func claimsOf(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// authorize runs /oauth/authorize with the harness's browser and follows the
// provider's own redirects. It returns the redirect to the client, or — when
// the provider stops to show a page — that page's response.
func (h *harness) authorize(clientID, redirectURI, scope string, extra url.Values) (*url.URL, *http.Response) {
	h.t.Helper()
	verifier := "verifier-0123456789abcdefghijklmnopqrstuvwxyz"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {redirectURI},
		"scope": {scope}, "state": {"st"}, "nonce": {"nc"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		q[k] = v
	}
	return h.follow(h.srv.URL+"/oauth/authorize?"+q.Encode(), redirectURI)
}

// follow requests target and follows redirects that stay on the provider,
// stopping at the first one that leaves for the client.
func (h *harness) follow(target, clientPrefix string) (*url.URL, *http.Response) {
	h.t.Helper()
	c := *h.client
	c.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), clientPrefix) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, err := c.Get(target)
	if err != nil {
		h.t.Fatal(err)
	}
	if loc := resp.Header.Get("Location"); resp.StatusCode == http.StatusFound && strings.HasPrefix(loc, clientPrefix) {
		resp.Body.Close()
		u, _ := url.Parse(loc)
		return u, nil
	}
	return nil, resp
}

const testVerifier = "verifier-0123456789abcdefghijklmnopqrstuvwxyz"

func (h *harness) token(form url.Values) (int, map[string]any) {
	h.t.Helper()
	resp, err := h.client.PostForm(h.srv.URL+"/oauth/token", form)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (h *harness) redeemCode(s *site, code string) map[string]any {
	h.t.Helper()
	status, out := h.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {s.url + "/auth/callback"},
		"client_id": {s.clientID}, "client_secret": {s.secret}, "code_verifier": {testVerifier},
	})
	if status != http.StatusOK {
		h.t.Fatalf("code exchange: %d %v", status, out)
	}
	return out
}

// ------------------------------------------------------------------ tests

// The regression test for the bug that cost ShortLinks the most: a synced
// passkey that enrolls and then fails every login because Backup Eligible was
// not persisted. Registration passing proves nothing; only the login leg does.
func TestRegisterThenLoginWithSyncedPasskey(t *testing.T) {
	h := newHarness(t)
	h.register("family@example.com")

	resp := h.login("family@example.com")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login after enrollment failed: %d %s", resp.StatusCode, bodyString(t, resp))
	}
	resp.Body.Close()

	var be bool
	var amr []string
	ctx := context.Background()
	_ = h.db.Pool().QueryRow(ctx, `SELECT backup_eligible FROM passkey_credentials LIMIT 1`).Scan(&be)
	_ = h.db.Pool().QueryRow(ctx, `SELECT amr FROM sso_sessions LIMIT 1`).Scan(&amr)
	if !be {
		t.Fatal("backup_eligible was not persisted; every synced passkey would fail to log in")
	}
	if strings.Join(amr, ",") != "swk,user" {
		t.Errorf("a synced passkey should authenticate as swk,user, got %v", amr)
	}
}

func TestAssertionCannotBeReplayed(t *testing.T) {
	h := newHarness(t)
	h.register("replay@example.com")

	resp := h.get("/accounts/v1/login/start?email=replay@example.com")
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	options, _ := virtualwebauthn.ParseAssertionOptions(string(raw))
	assertion := virtualwebauthn.CreateAssertionResponse(h.rp, h.auth, h.auth.Credentials[0], *options)

	first, _ := h.client.Post(h.srv.URL+"/accounts/v1/login/finish", "application/json", strings.NewReader(assertion))
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first assertion should succeed, got %d", first.StatusCode)
	}
	second, _ := h.client.Post(h.srv.URL+"/accounts/v1/login/finish", "application/json", strings.NewReader(assertion))
	second.Body.Close()
	if second.StatusCode == http.StatusOK {
		t.Fatal("the same assertion was accepted twice")
	}
}

func TestRegistrationStartDoesNotRevealExistingAccounts(t *testing.T) {
	h := newHarness(t)
	h.register("known@example.com")
	known := h.post("/accounts/v1/register/start", map[string]string{"email": "known@example.com"})
	unknown := h.post("/accounts/v1/register/start", map[string]string{"email": "stranger@example.com"})
	if kb, ub := bodyString(t, known), bodyString(t, unknown); known.StatusCode != unknown.StatusCode || kb != ub {
		t.Fatalf("responses differ: %d %q vs %d %q", known.StatusCode, kb, unknown.StatusCode, ub)
	}
}

// A real site signs in through the provider, and its access token carries
// exactly what a site needs: one audience, the session, and when the person
// authenticated.
func TestSiteSignsInThroughProvider(t *testing.T) {
	h := newHarness(t)
	h.register("site@example.com")
	s := h.newSite("groups")

	resp, err := h.client.Get(s.url + "/")
	if err != nil {
		t.Fatal(err)
	}
	if body := bodyString(t, resp); resp.StatusCode != http.StatusOK || body != "|" {
		t.Fatalf("site did not sign in: %d %q", resp.StatusCode, body)
	}
	sess := h.siteSession(s)
	if sess.RefreshToken == "" {
		t.Error("no refresh token: the site would sign out at the first access-token expiry")
	}
	c := claimsOf(t, sess.AccessToken)
	switch aud := c["aud"].(type) {
	case string:
		if aud != "groups" {
			t.Errorf("aud = %q, want groups", aud)
		}
	case []any:
		if len(aud) != 1 || aud[0] != "groups" {
			t.Errorf("aud = %v, want exactly [groups]", aud)
		}
	default:
		t.Errorf("aud missing: %v", c["aud"])
	}
	if c["sid"] == nil || c["auth_time"] == nil || c["apv"] != "1.0" {
		t.Errorf("access token lacks sid, auth_time or apv: %v", c)
	}
	if c["email"] != nil {
		t.Error("the site did not ask for email and must not receive it")
	}
}

// F3: presenting a refresh token that was already rotated away revokes its
// whole family, once the grace window has passed.
func TestRefreshReuseRevokesTheFamily(t *testing.T) {
	h := newHarness(t)
	h.register("reuse@example.com")
	s := h.newSite("groups")
	resp, _ := h.client.Get(s.url + "/")
	resp.Body.Close()
	r1 := h.siteSession(s).RefreshToken

	refresh := func(token string) (int, map[string]any) {
		return h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token},
			"client_id": {s.clientID}, "client_secret": {s.secret}})
	}
	status, out := refresh(r1)
	if status != http.StatusOK {
		t.Fatalf("first refresh: %d %v", status, out)
	}
	r2, _ := out["refresh_token"].(string)
	if r2 == "" || r2 == r1 {
		t.Fatal("the refresh token did not rotate")
	}
	// Inside the grace window a repeat is a race between two requests, not a theft.
	if status, _ := refresh(r1); status != http.StatusOK {
		t.Fatalf("a repeat inside the grace window was refused: %d", status)
	}
	if _, err := h.db.Pool().Exec(context.Background(),
		`UPDATE refresh_tokens SET rotated_at = now() - interval '5 minutes' WHERE rotated_at IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	if status, _ := refresh(r1); status == http.StatusOK {
		t.Fatal("a rotated-away token was accepted after the grace window")
	}
	if status, _ := refresh(r2); status == http.StatusOK {
		t.Fatal("reuse did not revoke the family: the successor still works")
	}
}

// F4: auth_time is when the person authenticated, and a refresh does not move it.
func TestAuthTimeIsTheCeremonyNotTheRefresh(t *testing.T) {
	h := newHarness(t)
	h.register("authtime@example.com")
	s := h.newSite("groups")
	resp, _ := h.client.Get(s.url + "/")
	resp.Body.Close()
	sess := h.siteSession(s)

	past := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	if _, err := h.db.Pool().Exec(context.Background(), `UPDATE refresh_tokens SET auth_time = $1`, past); err != nil {
		t.Fatal(err)
	}
	status, out := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {sess.RefreshToken},
		"client_id": {s.clientID}, "client_secret": {s.secret}})
	if status != http.StatusOK {
		t.Fatalf("refresh: %d %v", status, out)
	}
	at, _ := claimsOf(t, out["access_token"].(string))["auth_time"].(float64)
	if int64(at) != past.Unix() {
		t.Fatalf("auth_time after refresh = %d, want the ceremony's %d", int64(at), past.Unix())
	}
}

// F5: a client receives only the scopes it was registered for, and a third-party
// client cannot sign in while there is no consent screen.
func TestScopesAreLimitedToTheClient(t *testing.T) {
	h := newHarness(t)
	h.register("scopes@example.com")
	s := h.newSite("groups")

	loc, resp := h.authorize(s.clientID, s.url+"/auth/callback", "openid profile email offline_access", nil)
	if loc == nil {
		t.Fatalf("no redirect to the client: %d %s", resp.StatusCode, bodyString(t, resp))
	}
	out := h.redeemCode(s, loc.Query().Get("code"))
	if claimsOf(t, out["access_token"].(string))["email"] != nil {
		t.Error("a client not allowed email received it")
	}
	if !strings.Contains(out["scope"].(string), "profile") || strings.Contains(out["scope"].(string), "email") {
		t.Errorf("granted scope = %q", out["scope"])
	}

	third := h.newSite("stranger", func(c *store.Client) { c.TrustTier = "third_party" })
	loc, resp = h.authorize(third.clientID, third.url+"/auth/callback", "openid", nil)
	if loc == nil || loc.Query().Get("error") != "access_denied" {
		t.Fatalf("third-party client was not refused: %v %v", loc, resp)
	}
}

func TestPKCEAndRedirectURIsAreEnforced(t *testing.T) {
	h := newHarness(t)
	h.register("pkce@example.com")
	s := h.newSite("groups")

	loc, _ := h.authorize(s.clientID, s.url+"/auth/callback", "openid", url.Values{"code_challenge": {""}})
	if loc == nil || loc.Query().Get("code") != "" || loc.Query().Get("error") == "" {
		t.Fatalf("an authorization without PKCE was not refused: %v", loc)
	}

	loc, resp := h.authorize(s.clientID, "http://evil.example/callback", "openid", nil)
	if loc != nil {
		t.Fatalf("redirected to an unregistered URI: %v", loc)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unregistered redirect URI: status %d, want 400", resp.StatusCode)
	}
}

func TestSilentAuthorizeWithoutSession(t *testing.T) {
	h := newHarness(t)
	s := h.newSite("groups")
	loc, resp := h.authorize(s.clientID, s.url+"/auth/callback", "openid", url.Values{"prompt": {"none"}})
	if loc == nil {
		t.Fatalf("prompt=none showed a page: %d", resp.StatusCode)
	}
	if loc.Query().Get("error") != "login_required" {
		t.Fatalf("prompt=none without a session: %v", loc.Query())
	}
}

// Several accounts in one browser: a chooser when the request doesn't say which,
// a silent answer when it does, and account numbers that are never reused.
func TestSeveralAccountsInOneBrowser(t *testing.T) {
	h := newHarness(t)
	if n := h.register("alice@example.com"); n != 0 {
		t.Fatalf("first account is %d, want 0", n)
	}
	if n := h.register("bob@example.com"); n != 1 {
		t.Fatalf("second account is %d, want 1", n)
	}
	s := h.newSite("groups")
	redirect := s.url + "/auth/callback"

	loc, resp := h.authorize(s.clientID, redirect, "openid profile", nil)
	if loc != nil {
		t.Fatalf("with two accounts and no hint the provider picked one: %v", loc)
	}
	page := bodyString(t, resp)
	if !strings.Contains(page, "Choose an account") {
		t.Fatalf("expected the chooser, got %d %.200s", resp.StatusCode, page)
	}

	loc, _ = h.authorize(s.clientID, redirect, "openid", url.Values{"prompt": {"none"}})
	if loc == nil || loc.Query().Get("error") != "interaction_required" {
		t.Fatalf("prompt=none with two accounts: %v", loc)
	}

	loc, _ = h.authorize(s.clientID, redirect, "openid", url.Values{"login_hint": {"bob@example.com"}})
	if loc == nil || loc.Query().Get("code") == "" {
		t.Fatalf("login_hint did not select silently: %v", loc)
	}
	if sub := claimsOf(t, h.redeemCode(s, loc.Query().Get("code"))["access_token"].(string))["sub"]; sub != h.subjectOf("bob@example.com") {
		t.Fatalf("login_hint signed in %v, want bob", sub)
	}

	// Choosing from the page.
	m := regexp.MustCompile(`name="authRequestID" value="([^"]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("chooser has no authorization request id")
	}
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/login/select",
		strings.NewReader(url.Values{"authRequestID": {m[1]}, "account": {"0"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", h.srv.URL)
	c := *h.client
	c.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(r.URL.String(), redirect) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	chosen, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	chosen.Body.Close()
	cl, _ := url.Parse(chosen.Header.Get("Location"))
	if cl.Query().Get("code") == "" {
		t.Fatalf("choosing an account issued no code: %d %s", chosen.StatusCode, chosen.Header.Get("Location"))
	}
	if sub := claimsOf(t, h.redeemCode(s, cl.Query().Get("code"))["access_token"].(string))["sub"]; sub != h.subjectOf("alice@example.com") {
		t.Fatalf("chose account 0 but signed in %v", sub)
	}

	// Sign bob out, add carol: carol is 2, never 1.
	h.post("/accounts/v1/logout", map[string]int{"account": 1}).Body.Close()
	if n := h.register("carol@example.com"); n != 2 {
		t.Fatalf("a new account reused number %d", n)
	}
	stale := h.get("/u/1/")
	if body := bodyString(t, stale); stale.StatusCode != http.StatusNotFound || !strings.Contains(body, "isn't signed in here") {
		t.Fatalf("a stale account number did not show the chooser: %d", stale.StatusCode)
	}
}

func TestSignOutReachesSitesThroughBackchannelLogout(t *testing.T) {
	h := newHarness(t)
	h.register("signout@example.com")
	s := h.newSite("notes")
	ctx := context.Background()
	if err := h.db.SetBackchannelLogoutURI(ctx, s.clientID, s.url+"/auth/backchannel-logout"); err != nil {
		t.Fatal(err)
	}
	resp, _ := h.client.Get(s.url + "/")
	if body := bodyString(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("site did not sign in: %d %q", resp.StatusCode, body)
	}
	bad, _ := h.client.PostForm(s.url+"/auth/backchannel-logout", url.Values{"logout_token": {"not-a-token"}})
	bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Errorf("garbage logout token: %d, want 400", bad.StatusCode)
	}

	h.post("/accounts/v1/logout", nil).Body.Close()

	api, _ := h.client.Get(s.url + "/api/me")
	api.Body.Close()
	if api.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the site session survived signing out: %d", api.StatusCode)
	}
	var live int
	_ = h.db.Pool().QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL`).Scan(&live)
	if live != 0 {
		t.Errorf("%d refresh tokens survived sign-out", live)
	}
}

func TestProfileChangeReachesSitesThroughPushedEvent(t *testing.T) {
	h := newHarness(t)
	h.register("push@example.com")
	s := h.newSite("groups")
	if err := h.db.SetEventsURI(context.Background(), s.clientID, s.url+"/auth/events"); err != nil {
		t.Fatal(err)
	}
	resp, _ := h.client.Get(s.url + "/")
	if body := bodyString(t, resp); body != "|" {
		t.Fatalf("before any profile the site shows %q", body)
	}
	bad, _ := h.client.Post(s.url+"/auth/events", "application/secevent+jwt", strings.NewReader("not-a-token"))
	bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Errorf("garbage security event: %d, want 400", bad.StatusCode)
	}

	h.post("/accounts/v1/profile", map[string]any{"account": 0, "display_name": "Owl Person", "avatar": "owl"}).Body.Close()

	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, _ := h.client.Get(s.url + "/")
		body := bodyString(t, resp)
		if body == "Owl Person|🦉" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the site still shows %q after the profile was saved", body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// F2: many requests arriving as the access token expires refresh it once.
func TestConcurrentRequestsRefreshOnce(t *testing.T) {
	h := newHarness(t)
	h.register("race@example.com")
	s := h.newSite("groups")
	resp, _ := h.client.Get(s.url + "/")
	resp.Body.Close()

	sess := h.siteSession(s)
	sess.AccessExpiry = time.Now().Add(-time.Minute)
	if err := s.sessions.Put(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	h.tokenCalls.Store(0)

	var wg sync.WaitGroup
	var failed atomic.Int32
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := h.client.Get(s.url + "/api/me")
			if err != nil || r.StatusCode != http.StatusOK {
				failed.Add(1)
			}
			if r != nil {
				r.Body.Close()
			}
		}()
	}
	wg.Wait()
	if failed.Load() != 0 {
		t.Fatalf("%d of 10 concurrent requests were signed out", failed.Load())
	}
	if n := h.tokenCalls.Load(); n != 1 {
		t.Fatalf("token endpoint called %d times, want 1", n)
	}
}

// F10: discovery advertises only what is served.
func TestDiscoveryListsOnlyServedEndpoints(t *testing.T) {
	h := newHarness(t)
	resp := h.get("/.well-known/openid-configuration")
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	resp.Body.Close()
	if doc["issuer"] != h.srv.URL {
		t.Fatalf("issuer = %v", doc["issuer"])
	}
	checked := 0
	for k, v := range doc {
		u, ok := v.(string)
		if !ok || !(strings.HasSuffix(k, "_endpoint") || k == "jwks_uri") {
			continue
		}
		r, err := h.client.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode == http.StatusNotFound {
			t.Errorf("%s advertised at %s but returns 404", k, u)
		}
		checked++
	}
	if checked < 5 {
		t.Errorf("only %d endpoints advertised", checked)
	}
	pc := h.get("/.well-known/portiko-configuration")
	if body := bodyString(t, pc); !strings.Contains(body, `"protocol":"portiko"`) {
		t.Errorf("portiko configuration: %s", body)
	}
}

func TestSessionEndpointNamesTheAccount(t *testing.T) {
	h := newHarness(t)
	if r := h.get("/accounts/v1/session"); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("signed out: %d", r.StatusCode)
	}
	h.register("state@example.com")
	r := h.get("/accounts/v1/session?account=0")
	if cc := r.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	body := bodyString(t, r)
	if r.StatusCode != http.StatusOK || !strings.Contains(body, `"sid"`) || strings.Contains(body, "usr_") {
		t.Fatalf("session endpoint: %d %s", r.StatusCode, body)
	}
	if missing := h.get("/accounts/v1/session?account=9"); missing.StatusCode != http.StatusUnauthorized {
		t.Errorf("an account this browser doesn't hold: %d", missing.StatusCode)
	}
}

// The home page asks the passkey provider to rename a passkey once per profile
// version, not on every load: the provider shows a notification for each call.
func TestHomeSignalsPasskeyNameOncePerVersion(t *testing.T) {
	h := newHarness(t)
	h.register("signal@example.com")
	h.post("/accounts/v1/profile", map[string]any{"account": 0, "display_name": "Owl Person", "avatar": "owl"}).Body.Close()

	resp := h.get("/u/0/")
	page := bodyString(t, resp)
	if strings.Contains(page, "signalPasskeyDetails({") {
		t.Fatal("the home page signals the passkey name unconditionally on every load")
	}
	var version int64
	if err := h.db.Pool().QueryRow(context.Background(), `SELECT profile_updated_at FROM users LIMIT 1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`signalPasskeyDetailsOnce\(\{.*\},\s*` + strconv.FormatInt(version, 10) + `\s*\)`).MatchString(page) {
		t.Fatalf("the home page does not gate the signal on profile version %d", version)
	}
	if os.Getenv("NODE_CHECK") != "" {
		checkScripts(t, page)
	}
}

// The browser cookie is a credential, not an identifier of something harmless:
// anyone who can set accounts_sso to a value the database holds is signed in as
// that account. So only its hash is stored, and a dump or a backup is not a set
// of working cookies.
func TestBrowserCookieIsNeverStoredInPlaintext(t *testing.T) {
	h := newHarness(t)
	h.register("atrest@example.com")
	cookie := h.ssoCookie()
	ctx := context.Background()

	// Every column of both tables, not a list of column names: casting the whole
	// row to text catches a column added later that a test naming them one by one
	// would quietly stop covering.
	for _, table := range []string{"sso_sessions", "browsers"} {
		var leaked int
		if err := h.db.Pool().QueryRow(ctx,
			`SELECT count(*) FROM `+table+` t WHERE position($1 in t::text) > 0`, cookie).Scan(&leaked); err != nil {
			t.Fatalf("scanning %s: %v", table, err)
		}
		if leaked != 0 {
			t.Errorf("%s holds the cookie value in %d row(s)", table, leaked)
		}
	}

	// The plaintext column is gone from the schema, not merely left unwritten.
	var hasToken bool
	if err := h.db.Pool().QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		                 WHERE table_name = 'sso_sessions' AND column_name = 'token')`).Scan(&hasToken); err != nil {
		t.Fatal(err)
	}
	if hasToken {
		t.Error("sso_sessions still has a plaintext token column")
	}

	// What is stored is the hash — and the hash is the lookup key, not a column
	// written and then ignored: the cookie the browser sent still resolves it.
	var stored string
	if err := h.db.Pool().QueryRow(ctx, `SELECT browser_hash FROM sso_sessions`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if want := store.HashToken(cookie); stored != want {
		t.Errorf("browser_hash is %q, want HashToken(cookie) %q", stored, want)
	}
	sessions, err := h.db.Sessions(ctx, cookie)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("the cookie resolved %d sessions (err %v), want 1", len(sessions), err)
	}
}

// Recovery enrolls a new passkey on an existing account on the strength of
// reading its email. That is the designed root of trust, so it has to be
// visible: without a notice, anyone who takes over the mailbox has a permanent,
// silent passkey, and the holder has nothing to notice. AccountsWeb #0013.
func TestRecoveryNotifiesTheAccountHolder(t *testing.T) {
	h := newHarness(t)
	// A known AAGUID, so the notice can name the authenticator. That half of the
	// message is what lets a holder recognise an enrollment as their own.
	h.auth.Aaguid = [16]byte{0xfb, 0xfc, 0x30, 0x07, 0x15, 0x4e, 0x4e, 0xcc,
		0x8c, 0x0b, 0x6e, 0x02, 0x05, 0x57, 0xd7, 0xbd} // iCloud Keychain

	const email = "recover@example.com"
	h.register(email)

	// A first registration is the person sitting in the flow. Telling them what
	// they are doing teaches them to ignore the message that matters.
	if n := h.mail.notices(); len(n) != 0 {
		t.Fatalf("a first registration sent %d passkey notices, want 0: %+v", len(n), n)
	}
	if rows := h.auditRows(store.AuditAccountRecovered); len(rows) != 0 {
		t.Errorf("a first registration wrote %d account.recovered rows, want 0", len(rows))
	}
	// But it does write credential.added: a trail with a hole where the account
	// began cannot be read backwards.
	added := h.auditRows(store.AuditCredentialAdded)
	if len(added) != 1 {
		t.Fatalf("a first registration wrote %d credential.added rows, want 1", len(added))
	}

	// Registering the same address again is recovery, not a second account.
	h.register(email)

	notices := h.mail.notices()
	if len(notices) != 1 {
		t.Fatalf("recovery sent %d passkey notices, want 1: %+v", len(notices), notices)
	}
	got := notices[0]
	if got.to != email {
		t.Errorf("notice went to %q, want the account's primary address %q", got.to, email)
	}
	if got.notice.Authenticator != "iCloud Keychain" {
		t.Errorf("notice names the authenticator %q, want %q", got.notice.Authenticator, "iCloud Keychain")
	}
	if !strings.HasPrefix(got.notice.ReviewURL, h.srv.URL) {
		t.Errorf("notice points at %q, which is not this deployment", got.notice.ReviewURL)
	}
	if got.notice.When.IsZero() {
		t.Error("notice does not say when the passkey was added")
	}

	// Two credentials on one account, and the audit trail says how the second
	// one arrived and from where.
	var creds int
	if err := h.db.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM passkey_credentials`).Scan(&creds); err != nil {
		t.Fatal(err)
	}
	if creds != 2 {
		t.Fatalf("recovery left %d credentials, want 2 on one account", creds)
	}
	recovered := h.auditRows(store.AuditAccountRecovered)
	if len(recovered) != 1 {
		t.Fatalf("recovery wrote %d account.recovered rows, want 1", len(recovered))
	}
	if added = h.auditRows(store.AuditCredentialAdded); len(added) != 2 {
		t.Fatalf("after recovery there are %d credential.added rows, want 2", len(added))
	}
	for _, r := range append(recovered, added[1]) {
		if r.ip == "" || r.userAgent == "" {
			t.Errorf("audit row has no caller: ip=%q user_agent=%q", r.ip, r.userAgent)
		}
		if !strings.Contains(r.detail, "iCloud Keychain") {
			t.Errorf("audit detail does not name the authenticator: %s", r.detail)
		}
	}
}

// checkScripts syntax-checks every inline script with node, when asked to.
func checkScripts(t *testing.T, page string) {
	t.Helper()
	for i, m := range regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindAllStringSubmatch(page, -1) {
		f, err := os.CreateTemp(t.TempDir(), "script-*.js")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString(m[1])
		f.Close()
		if out, err := exec.Command("node", "--check", f.Name()).CombinedOutput(); err != nil {
			t.Errorf("script %d does not parse: %v\n%s", i, err, out)
		}
	}
}
