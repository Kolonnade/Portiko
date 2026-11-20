package provider_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/Kolonnade/Portiko/internal/accounts"
	"github.com/Kolonnade/Portiko/internal/store"
	"github.com/Kolonnade/Portiko/provider"
	"github.com/Kolonnade/Portiko/rp/session"
)

const goodPassword = "plum tree under the north window"

// newPasswordHarness is a harness with PASSWORDS=allow.
func newPasswordHarness(t *testing.T) *harness {
	t.Helper()
	t.Setenv("PASSWORDS", "allow")
	return newHarness(t)
}

// call is a browser's fetch: JSON, from the provider's own origin. It returns
// the decoded body and the raw one.
func (h *harness) call(path string, body any) (int, map[string]any, string) {
	h.t.Helper()
	blob, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+h.prefix+path, bytes.NewReader(blob))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", h.srv.URL)
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	raw := bodyString(h.t, resp)
	var out map[string]any
	_ = json.Unmarshal([]byte(raw), &out)
	return resp.StatusCode, out, raw
}

// verifyCode asks for a code and verifies it, returning the verify answer.
func (h *harness) verifyCode(email string) map[string]any {
	h.t.Helper()
	if resp := h.post("/accounts/v1/register/start", map[string]string{"email": email}); resp.StatusCode != http.StatusAccepted {
		h.t.Fatalf("register/start: %s", bodyString(h.t, resp))
	}
	resp := h.post("/accounts/v1/register/verify", map[string]string{"email": email, "code": h.latestCode(email)})
	raw := bodyString(h.t, resp)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("register/verify: %d %s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

// registerWithPassword enrolls (or recovers) email by choosing a password after
// the code, and returns the account number.
func (h *harness) registerWithPassword(email, pw string) int {
	h.t.Helper()
	v := h.verifyCode(email)
	tok, _ := v["password_token"].(string)
	if tok == "" {
		h.t.Fatalf("register/verify gave no password_token: %v", v)
	}
	status, out, raw := h.call("/accounts/v1/register/password", map[string]string{"token": tok, "password": pw})
	if status != http.StatusOK {
		h.t.Fatalf("register/password: %d %s", status, raw)
	}
	return int(out["account"].(float64))
}

func (h *harness) passwordLogin(email, pw string) (int, map[string]any, string) {
	h.t.Helper()
	return h.call("/accounts/v1/login/password", map[string]string{"email": email, "password": pw})
}

func (h *harness) sessionAMR(email string) []string {
	h.t.Helper()
	var amr []string
	if err := h.db.Pool().QueryRow(context.Background(),
		`SELECT s.amr FROM sso_sessions s JOIN identifiers i ON i.user_id = s.user_id WHERE i.value = $1`,
		store.NormalizeEmail(email)).Scan(&amr); err != nil {
		h.t.Fatalf("reading the session amr: %v", err)
	}
	return amr
}

func (h *harness) logoutAll() {
	h.t.Helper()
	resp := h.post("/accounts/v1/logout", map[string]any{})
	resp.Body.Close()
}

func TestPasswordsAreOffByDefault(t *testing.T) {
	h := newHarness(t)
	v := h.verifyCode("off@example.com")
	if _, ok := v["password_token"]; ok {
		t.Fatalf("register/verify offered a password with PASSWORDS unset: %v", v)
	}
	for _, path := range []string{"/accounts/v1/register/password", "/accounts/v1/login/password", "/accounts/v1/password"} {
		status, out, _ := h.call(path, map[string]any{"token": "x", "email": "off@example.com", "password": goodPassword, "account": 0})
		if status != http.StatusNotFound || out["error"] != "passwords_not_enabled" {
			t.Errorf("%s with passwords off: %d %v, want 404 passwords_not_enabled", path, status, out)
		}
	}
	page := bodyString(t, h.get("/signin"))
	if strings.Contains(page, `id="password"`) {
		t.Error("the sign-in page offers a password with PASSWORDS unset")
	}
}

func TestEnrollWithPasswordThenSignIn(t *testing.T) {
	h := newPasswordHarness(t)
	n := h.registerWithPassword("pw@example.com", goodPassword)
	if amr := strings.Join(h.sessionAMR("pw@example.com"), ","); amr != "pwd" {
		t.Errorf("enrollment session amr = %q, want pwd", amr)
	}
	if rows := h.auditRows(store.AuditPasswordSet); len(rows) != 1 || !strings.Contains(rows[0].detail, `"recovery": false`) {
		t.Errorf("password.set audit rows: %+v", rows)
	}
	if len(h.mail.passwordNotices()) != 0 {
		t.Error("a first enrollment sent a password notice to the person sitting in the flow")
	}
	var passkeys int
	_ = h.db.Pool().QueryRow(context.Background(), `SELECT count(*) FROM passkey_credentials`).Scan(&passkeys)
	if passkeys != 0 {
		t.Errorf("%d passkeys enrolled by the password path", passkeys)
	}

	h.logoutAll()
	status, out, raw := h.passwordLogin("PW@example.com ", goodPassword)
	if status != http.StatusOK || out["status"] != "signed_in" || int(out["account"].(float64)) < 0 {
		t.Fatalf("password sign-in: %d %s", status, raw)
	}
	_ = n
	if amr := strings.Join(h.sessionAMR("pw@example.com"), ","); amr != "pwd" {
		t.Errorf("sign-in session amr = %q, want pwd", amr)
	}
	var lastUsed *time.Time
	_ = h.db.Pool().QueryRow(context.Background(), `SELECT last_used_at FROM passwords`).Scan(&lastUsed)
	if lastUsed == nil {
		t.Error("last_used_at did not move")
	}

	// Wrong password, unknown address, an account with no password: one answer.
	h.register("passkeyonly@example.com")
	_, _, wrong := h.passwordLogin("pw@example.com", goodPassword+"!")
	_, _, unknown := h.passwordLogin("nobody@example.com", goodPassword)
	_, _, nopw := h.passwordLogin("passkeyonly@example.com", goodPassword)
	if wrong != unknown || wrong != nopw || !strings.Contains(wrong, "authentication_failed") {
		t.Errorf("failures are distinguishable:\n wrong   %s\n unknown %s\n no pw   %s", wrong, unknown, nopw)
	}
}

func TestWeakPasswordKeepsTheToken(t *testing.T) {
	h := newPasswordHarness(t)
	v := h.verifyCode("weak@example.com")
	tok := v["password_token"].(string)
	for _, pw := range []string{"short one", "123456789012345", "weak@example.com", "passwordpassword"} {
		status, out, _ := h.call("/accounts/v1/register/password", map[string]string{"token": tok, "password": pw})
		if status != http.StatusBadRequest || out["error"] != "weak_password" || out["error_description"] == "" {
			t.Errorf("%q: %d %v, want 400 weak_password with a reason", pw, status, out)
		}
	}
	status, _, raw := h.call("/accounts/v1/register/password", map[string]string{"token": tok, "password": goodPassword})
	if status != http.StatusOK {
		t.Fatalf("a good password after weak ones: %d %s", status, raw)
	}
	// The token finishes one ceremony only, by either path.
	if status, out, _ := h.call("/accounts/v1/register/password", map[string]string{"token": tok, "password": goodPassword}); status != http.StatusUnauthorized {
		t.Errorf("reusing the token: %d %v, want 401", status, out)
	}
	if status, _, _ := h.call("/accounts/v1/register/password", map[string]string{"token": "made-up", "password": goodPassword}); status != http.StatusUnauthorized {
		t.Errorf("a made-up token: %d, want 401", status)
	}
}

func TestPasswordEndpointsRequireTheSameOrigin(t *testing.T) {
	h := newPasswordHarness(t)
	h.registerWithPassword("origin@example.com", goodPassword)
	h.logoutAll()
	for _, origin := range []string{"", "https://evil.example"} {
		blob, _ := json.Marshal(map[string]string{"email": "origin@example.com", "password": goodPassword})
		req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/accounts/v1/login/password", bytes.NewReader(blob))
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Origin %q: %d, want 403", origin, resp.StatusCode)
		}
	}
	form := url.Values{"email": {"origin@example.com"}, "password": {goodPassword}}
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/accounts/v1/login/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", h.srv.URL)
	resp, _ := h.client.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("a form post: %d, want 415", resp.StatusCode)
	}
}

// Past the free attempts each failure makes the next attempt wait, and while
// it waits even the right password is refused, with the same answer.
func TestPasswordBackoff(t *testing.T) {
	h := newPasswordHarness(t)
	h.registerWithPassword("backoff@example.com", goodPassword)
	h.logoutAll()
	for i := 0; i <= store.FreePasswordAttempts; i++ {
		if status, _, _ := h.passwordLogin("backoff@example.com", "not the password at all"); status != http.StatusUnauthorized {
			t.Fatalf("wrong password %d: %d", i, status)
		}
	}
	var locked *time.Time
	_ = h.db.Pool().QueryRow(context.Background(), `SELECT locked_until FROM passwords`).Scan(&locked)
	if locked == nil {
		t.Fatal("no backoff after the free attempts")
	}
	if d := time.Until(*locked); d < store.PasswordBackoffBase-5*time.Second || d > store.PasswordBackoffBase+5*time.Second {
		t.Errorf("first wait is %v, want about %v", d, store.PasswordBackoffBase)
	}
	status, _, raw := h.passwordLogin("backoff@example.com", goodPassword)
	_, _, unknown := h.passwordLogin("nobody@example.com", goodPassword)
	if status != http.StatusUnauthorized || raw != unknown {
		t.Fatalf("the right password while backing off: %d %s", status, raw)
	}

	h.execSQL(`UPDATE passwords SET locked_until = now() - interval '1 second'`)
	if status, _, raw := h.passwordLogin("backoff@example.com", "still not the password"); status != http.StatusUnauthorized {
		t.Fatalf("after the wait: %d %s", status, raw)
	}
	_ = h.db.Pool().QueryRow(context.Background(), `SELECT locked_until FROM passwords`).Scan(&locked)
	if locked == nil || time.Until(*locked) < 2*store.PasswordBackoffBase-5*time.Second {
		t.Errorf("the second wait did not double: %v", locked)
	}

	h.execSQL(`UPDATE passwords SET locked_until = now() - interval '1 second'`)
	if status, _, raw := h.passwordLogin("backoff@example.com", goodPassword); status != http.StatusOK {
		t.Fatalf("the right password after the wait: %d %s", status, raw)
	}
	var failed int
	_ = h.db.Pool().QueryRow(context.Background(), `SELECT failed_attempts, locked_until FROM passwords`).Scan(&failed, &locked)
	if failed != 0 || locked != nil {
		t.Errorf("a success left failed_attempts=%d locked_until=%v", failed, locked)
	}
}

// Parallel guesses queue on the row, so a burst cannot all slip in before the
// backoff is recorded.
func TestParallelPasswordGuessesAreCounted(t *testing.T) {
	h := newPasswordHarness(t)
	h.registerWithPassword("burst@example.com", goodPassword)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.passwordLogin("burst@example.com", "a wrong guess, sent at once")
		}()
	}
	wg.Wait()
	var failed int
	_ = h.db.Pool().QueryRow(context.Background(), `SELECT failed_attempts FROM passwords`).Scan(&failed)
	if failed != store.FreePasswordAttempts+1 {
		t.Errorf("failed_attempts = %d after a burst of 8, want %d (the rest refused while backing off)", failed, store.FreePasswordAttempts+1)
	}
}

func TestPasswordSignInIsRateLimitedPerAddress(t *testing.T) {
	h := newPasswordHarness(t)
	var last int
	for i := 0; i < 11; i++ {
		last, _, _ = h.passwordLogin("limited@example.com", goodPassword)
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("the 11th attempt in an hour: %d, want 429", last)
	}
}

// Recovery offers the password too, and a password set that way is held like
// a recovered passkey, announced, and leaves the passkeys alone.
func TestRecoveryCanSetAPassword(t *testing.T) {
	h := newPasswordHarness(t)
	n := h.register("rec@example.com")
	original := h.listPasskeys(n)[0].ID
	h.logoutAll()

	v := h.verifyCode("rec@example.com")
	if v["purpose"] != "recovery" {
		t.Fatalf("purpose = %v", v["purpose"])
	}
	status, out, raw := h.call("/accounts/v1/register/password", map[string]string{"token": v["password_token"].(string), "password": goodPassword})
	if status != http.StatusOK {
		t.Fatalf("recovery with a password: %d %s", status, raw)
	}
	m := int(out["account"].(float64))
	if len(h.listPasskeys(m)) != 1 {
		t.Error("recovery with a password changed the passkeys")
	}
	var until *time.Time
	_ = h.db.Pool().QueryRow(context.Background(), `SELECT restricted_until FROM passwords`).Scan(&until)
	if until == nil || time.Until(*until) < accounts.RecoveryHold-time.Minute {
		t.Errorf("the recovered password's hold: %v", until)
	}
	if rows := h.auditRows(store.AuditAccountRecovered); len(rows) != 1 {
		t.Errorf("account.recovered rows: %+v", rows)
	}
	notes := h.mail.passwordNotices()
	if len(notes) != 1 || notes[0].to != "rec@example.com" || !notes[0].notice.Recovery || notes[0].notice.Change != provider.PasswordAdded {
		t.Errorf("password notices: %+v", notes)
	}
	// The held session cannot take the passkey away.
	if code, reply := h.postSameOrigin(passkeyPath(original, "revoke"), map[string]any{"account": m}); code != http.StatusForbidden || reply.Error != "recovery_hold" {
		t.Errorf("revoke from a recovered-password session: %d %s", code, reply.Error)
	}
	// Signing in with that password later is held too.
	h.logoutAll()
	if status, _, raw := h.passwordLogin("rec@example.com", goodPassword); status != http.StatusOK {
		t.Fatalf("sign-in: %d %s", status, raw)
	}
	if code, reply := h.postSameOrigin(passkeyPath(original, "revoke"), map[string]any{"account": m}); code != http.StatusForbidden || reply.Error != "recovery_hold" {
		t.Errorf("revoke after signing in with the recovered password: %d %s", code, reply.Error)
	}

	// Recovering a forgotten password replaces it.
	v = h.verifyCode("rec@example.com")
	if status, _, raw := h.call("/accounts/v1/register/password", map[string]string{"token": v["password_token"].(string), "password": "a different and new phrase"}); status != http.StatusOK {
		t.Fatalf("second recovery: %d %s", status, raw)
	}
	if status, _, _ := h.passwordLogin("rec@example.com", goodPassword); status != http.StatusUnauthorized {
		t.Error("the replaced password still signs in")
	}
	if notes := h.mail.passwordNotices(); len(notes) != 2 || notes[1].notice.Change != provider.PasswordReplaced {
		t.Errorf("replacement notice: %+v", notes)
	}
}

// A password-only account adds a passkey through the email code, then can drop
// the password, but only from a session that is not held.
func TestPasswordOnlyAccountMovesToAPasskey(t *testing.T) {
	h := newPasswordHarness(t)
	n := h.registerWithPassword("mover@example.com", goodPassword)
	if status, out, _ := h.call("/accounts/v1/password/remove", map[string]any{"account": n}); status != http.StatusConflict || out["error"] != "cannot_remove_last_credential" {
		t.Fatalf("removing the only credential: %d %v", status, out)
	}

	// Recovery for an account with no passkey mints its first handle.
	if m := h.register("mover@example.com"); m != n {
		t.Fatalf("recovery signed in as %d, want %d", m, n)
	}
	if len(h.listPasskeys(n)) != 1 {
		t.Fatal("no passkey after recovery")
	}
	h.loginOK("mover@example.com")
	// That passkey is held: it cannot remove the password yet.
	if status, out, _ := h.call("/accounts/v1/password/remove", map[string]any{"account": n}); status != http.StatusForbidden || out["error"] != "recovery_hold" {
		t.Fatalf("removing the password from a held session: %d %v", status, out)
	}
	// The password the holder already had is not held, and can.
	if status, _, raw := h.passwordLogin("mover@example.com", goodPassword); status != http.StatusOK {
		t.Fatalf("password sign-in: %d %s", status, raw)
	}
	status, out, raw := h.call("/accounts/v1/password/remove", map[string]any{"account": n})
	if status != http.StatusOK || out["password"] != nil {
		t.Fatalf("removing the password: %d %s", status, raw)
	}
	if rows := h.auditRows(store.AuditPasswordRemoved); len(rows) != 1 {
		t.Errorf("password.removed rows: %+v", rows)
	}
	if status, _, _ := h.passwordLogin("mover@example.com", goodPassword); status != http.StatusUnauthorized {
		t.Error("a removed password still signs in")
	}
	h.loginOK("mover@example.com")
}

func TestAccountPageSetsChangesAndRemovesAPassword(t *testing.T) {
	h := newPasswordHarness(t)
	n := h.register("page@example.com")
	resp := h.get("/accounts/v1/password?account=" + strconv.Itoa(n))
	var state map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&state)
	resp.Body.Close()
	if state["password"] != nil || state["allowed"] != true {
		t.Fatalf("GET password on a passkey account: %v", state)
	}

	if status, out, _ := h.call("/accounts/v1/password", map[string]any{"account": n, "password": "too short"}); status != http.StatusBadRequest || out["error"] != "weak_password" {
		t.Errorf("weak: %d %v", status, out)
	}
	if status, out, _ := h.call("/accounts/v1/password", map[string]any{"password": goodPassword}); status != http.StatusBadRequest {
		t.Errorf("no account: %d %v", status, out)
	}
	status, out, raw := h.call("/accounts/v1/password", map[string]any{"account": n, "password": goodPassword})
	if status != http.StatusOK || out["password"] == nil {
		t.Fatalf("add: %d %s", status, raw)
	}
	if status, _, raw := h.call("/accounts/v1/password", map[string]any{"account": n, "password": "another phrase entirely"}); status != http.StatusOK {
		t.Fatalf("change: %d %s", status, raw)
	}
	notes := h.mail.passwordNotices()
	if len(notes) != 2 || notes[0].notice.Change != provider.PasswordAdded || notes[1].notice.Change != provider.PasswordReplaced || notes[0].notice.Recovery {
		t.Errorf("notices: %+v", notes)
	}
	if len(h.auditRows(store.AuditPasswordSet)) != 1 || len(h.auditRows(store.AuditPasswordChanged)) != 1 {
		t.Error("missing password.set or password.changed audit rows")
	}

	// A stale sign-in cannot add, change or remove.
	h.ageSessions()
	for _, path := range []string{"/accounts/v1/password", "/accounts/v1/password/remove"} {
		if status, out, _ := h.call(path, map[string]any{"account": n, "password": "yet another long phrase"}); status != http.StatusForbidden || out["error"] != "reauthentication_required" {
			t.Errorf("%s with a stale sign-in: %d %v", path, status, out)
		}
	}
	// Signing in again with the password is the re-authentication.
	if status, _, raw := h.passwordLogin("page@example.com", "another phrase entirely"); status != http.StatusOK {
		t.Fatalf("re-auth with the password: %d %s", status, raw)
	}
	if status, _, raw := h.call("/accounts/v1/password/remove", map[string]any{"account": n}); status != http.StatusOK {
		t.Fatalf("remove: %d %s", status, raw)
	}
	if status, out, _ := h.call("/accounts/v1/password/remove", map[string]any{"account": n}); status != http.StatusNotFound {
		t.Errorf("removing a password that is gone: %d %v", status, out)
	}
}

// With a password on the account the last passkey may go; then the password
// is the last credential and may not.
func TestLastCredentialCountsThePassword(t *testing.T) {
	h := newPasswordHarness(t)
	n := h.register("last@example.com")
	only := h.listPasskeys(n)[0].ID
	if code, reply := h.postSameOrigin(passkeyPath(only, "revoke"), map[string]any{"account": n}); code != http.StatusConflict {
		t.Fatalf("revoking the only passkey with no password: %d %s", code, reply.Error)
	}
	if status, _, raw := h.call("/accounts/v1/password", map[string]any{"account": n, "password": goodPassword}); status != http.StatusOK {
		t.Fatalf("add a password: %d %s", status, raw)
	}
	if code, reply := h.postSameOrigin(passkeyPath(only, "revoke"), map[string]any{"account": n}); code != http.StatusOK {
		t.Fatalf("revoking the only passkey with a password: %d %s", code, reply.Error)
	}
	if status, out, _ := h.call("/accounts/v1/password/remove", map[string]any{"account": n}); status != http.StatusConflict {
		t.Fatalf("removing the password, now the last credential: %d %v", status, out)
	}
}

// Revoking the last passkey and removing the password at once: one wins.
func TestConcurrentRevokeAndPasswordRemovalLeaveOne(t *testing.T) {
	h := newPasswordHarness(t)
	for round := 0; round < 3; round++ {
		email := "race" + strconv.Itoa(round) + "@example.com"
		n := h.register(email)
		only := h.listPasskeys(n)[0].ID
		if status, _, raw := h.call("/accounts/v1/password", map[string]any{"account": n, "password": goodPassword}); status != http.StatusOK {
			t.Fatalf("add a password: %d %s", status, raw)
		}
		codes := make([]int, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			codes[0], _ = h.postSameOrigin(passkeyPath(only, "revoke"), map[string]any{"account": n})
		}()
		go func() {
			defer wg.Done()
			codes[1], _, _ = h.call("/accounts/v1/password/remove", map[string]any{"account": n})
		}()
		wg.Wait()
		if count(codes, 200) != 1 || count(codes, 409) != 1 {
			t.Fatalf("round %d: statuses %v, want one 200 and one 409", round, codes)
		}
	}
}

func TestTurningPasswordsOffStopsThem(t *testing.T) {
	h := newPasswordHarness(t)
	n := h.register("later@example.com")
	if status, _, raw := h.call("/accounts/v1/password", map[string]any{"account": n, "password": goodPassword}); status != http.StatusOK {
		t.Fatalf("add a password: %d %s", status, raw)
	}
	t.Setenv("PASSWORDS", "off")
	cfg, err := provider.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	p, err := provider.New(context.Background(), cfg, provider.Options{Mailer: h.mail})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	h.handler.Store(p.Handler())
	if status, _, _ := h.passwordLogin("later@example.com", goodPassword); status != http.StatusNotFound {
		t.Errorf("password sign-in with passwords off: %d, want 404", status)
	}
	// An account can still drop the password it has.
	if status, _, raw := h.call("/accounts/v1/password/remove", map[string]any{"account": n}); status != http.StatusOK {
		t.Errorf("remove with passwords off: %d %s", status, raw)
	}
}

// ------------------------------------------------- a scripted relying party

// scripted is the client an end-to-end suite uses: plain HTTP with a cookie
// jar, no browser, following redirects the way a browser does.
type scripted struct {
	t      *testing.T
	c      *http.Client
	issuer string
}

func newScripted(t *testing.T, issuer string) *scripted {
	jar, _ := cookiejar.New(nil)
	return &scripted{t: t, c: &http.Client{Jar: jar, Timeout: 10 * time.Second}, issuer: issuer}
}

// get follows redirects and returns the final URL and body.
func (s *scripted) get(u string) (*url.URL, int, string) {
	s.t.Helper()
	resp, err := s.c.Get(u)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.Request.URL, resp.StatusCode, string(b)
}

// post sends JSON with the provider's Origin, as the sign-in page's fetch does.
func (s *scripted) post(path string, body any) (int, map[string]any) {
	s.t.Helper()
	blob, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, s.issuer+path, bytes.NewReader(blob))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", s.issuer)
	resp, err := s.c.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// signInPage opens the site, which sends the client through the provider to
// its sign-in page, and returns the authorization request's id from its URL.
func (s *scripted) signInPage(siteURL string) string {
	s.t.Helper()
	final, status, _ := s.get(siteURL + "/")
	if status != http.StatusOK || final.Path != "/signin" || final.Query().Get("authRequestID") == "" {
		s.t.Fatalf("the site did not send the client to the sign-in page: %d %s", status, final)
	}
	return final.Query().Get("authRequestID")
}

// The end-to-end path a downstream suite runs headlessly: enroll through a
// site with an emailed code and a password, then sign in to the site with the
// password, each through an OpenID Connect authorization-code flow.
func TestScriptedClientEnrollsAndSignsInWithAPassword(t *testing.T) {
	h := newPasswordHarness(t)
	s := h.newSite("agora")
	email := "e2e@example.test"

	// Enroll.
	c := newScripted(t, h.srv.URL)
	id := c.signInPage(s.url)
	q := "?authRequestID=" + url.QueryEscape(id)
	if status, _ := c.post("/accounts/v1/register/start"+q, map[string]string{"email": email}); status != http.StatusAccepted {
		t.Fatalf("register/start: %d", status)
	}
	status, v := c.post("/accounts/v1/register/verify"+q, map[string]string{"email": email, "code": h.latestCode(email)})
	if status != http.StatusOK || v["password_token"] == nil {
		t.Fatalf("register/verify: %d %v", status, v)
	}
	status, done := c.post("/accounts/v1/register/password"+q, map[string]any{"token": v["password_token"], "password": goodPassword})
	if status != http.StatusOK {
		t.Fatalf("register/password: %d %v", status, done)
	}
	final, status, body := c.get(done["redirect"].(string))
	if status != http.StatusOK || final.Host != strings.TrimPrefix(s.url, "http://") || final.Path != "/" {
		t.Fatalf("after enrolling, the site answered %d at %s: %s", status, final, body)
	}
	idToken := h.siteSessionFor(s, c.c).IDToken
	if amr, _ := claimsOf(t, idToken)["amr"].([]any); len(amr) != 1 || amr[0] != "pwd" {
		t.Errorf("enrollment id token amr = %v, want [pwd]", claimsOf(t, idToken)["amr"])
	}

	// Sign in, from a fresh client that has never seen the provider.
	c = newScripted(t, h.srv.URL)
	id = c.signInPage(s.url)
	q = "?authRequestID=" + url.QueryEscape(id)
	status, done = c.post("/accounts/v1/login/password"+q, map[string]string{"email": email, "password": goodPassword})
	if status != http.StatusOK {
		t.Fatalf("login/password: %d %v", status, done)
	}
	final, status, body = c.get(done["redirect"].(string))
	if status != http.StatusOK || final.Path != "/" || !strings.HasPrefix(final.String(), s.url) {
		t.Fatalf("after signing in, the site answered %d at %s: %s", status, final, body)
	}
	sess := h.siteSessionFor(s, c.c)
	c2 := claimsOf(t, sess.IDToken)
	if amr, _ := c2["amr"].([]any); len(amr) != 1 || amr[0] != "pwd" {
		t.Errorf("sign-in id token amr = %v, want [pwd]", c2["amr"])
	}
	if sess.Subject != h.subjectOf(email) {
		t.Errorf("signed in as %q, want %q", sess.Subject, h.subjectOf(email))
	}
	if ac := claimsOf(t, sess.AccessToken); ac["amr"] == nil {
		t.Logf("access token carries no amr: %v", ac)
	}
}

// A passkey sign-in still reports what it did before passwords existed.
func TestPasskeyAMRIsUnchanged(t *testing.T) {
	h := newPasswordHarness(t)
	h.register("pk@example.com")
	if amr := strings.Join(h.sessionAMR("pk@example.com"), ","); amr != "swk,user" {
		t.Errorf("passkey amr = %q, want swk,user", amr)
	}
	// A virtual passkey that cannot be backed up reports hwk.
	h.auth = virtualwebauthn.NewAuthenticator()
	h.register("hw@example.com")
	if amr := strings.Join(h.sessionAMR("hw@example.com"), ","); amr != "hwk,user" {
		t.Errorf("hardware passkey amr = %q, want hwk,user", amr)
	}
}

// siteSessionFor returns the site's session for a client other than the
// harness's own.
func (h *harness) siteSessionFor(s *site, c *http.Client) *session.Session {
	h.t.Helper()
	u, _ := url.Parse(s.url)
	for _, ck := range c.Jar.Cookies(u) {
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

func TestPagesOfferThePasswordWhenAllowed(t *testing.T) {
	h := newPasswordHarness(t)
	signin := bodyString(t, h.get("/signin"))
	for _, want := range []string{`id="passwordSignIn"`, `autocomplete="current-password"`, `id="chooseStep"`,
		`id="choosePasskey"`, `id="choosePassword"`, `autocomplete="new-password"`, `const PASSWORDS =  true `} {
		if !strings.Contains(signin, want) {
			t.Errorf("sign-in page lacks %q", want)
		}
	}
	// The passkey comes first: it is the recommended one.
	if strings.Index(signin, `id="choosePasskey"`) > strings.Index(signin, `id="choosePassword"`) {
		t.Error("the password is offered before the passkey")
	}

	n := h.register("pages@example.com")
	page := bodyString(t, h.get("/u/"+strconv.Itoa(n)+"/passkeys"))
	for _, want := range []string{"<h2>Password</h2>", `id="passwordForm"`, "Add a password", "const REAUTH_PASSWORD =  false "} {
		if !strings.Contains(page, want) {
			t.Errorf("passkeys page lacks %q", want)
		}
	}
	if strings.Contains(page, `id="removePassword"`) {
		t.Error("an account with no password is offered to remove one")
	}
	if status, _, raw := h.call("/accounts/v1/password", map[string]any{"account": n, "password": goodPassword}); status != http.StatusOK {
		t.Fatalf("add a password: %d %s", status, raw)
	}
	page = bodyString(t, h.get("/u/"+strconv.Itoa(n)+"/passkeys"))
	for _, want := range []string{"Change password", `id="removePassword"`, "const REAUTH_PASSWORD =  true ", "never used to sign in"} {
		if !strings.Contains(page, want) {
			t.Errorf("passkeys page with a password lacks %q", want)
		}
	}
	emails := bodyString(t, h.get("/u/"+strconv.Itoa(n)+"/emails"))
	if !strings.Contains(emails, "const REAUTH_PASSWORD =  true ") {
		t.Error("the emails page does not offer the password to confirm a change")
	}
	if home := bodyString(t, h.get("/u/"+strconv.Itoa(n)+"/")); !strings.Contains(home, "Passkeys and password") {
		t.Error("the home page does not link to the password")
	}
	if os.Getenv("NODE_CHECK") != "" {
		checkScripts(t, signin)
		checkScripts(t, page)
		checkScripts(t, emails)
	}
}

func TestPagesHideThePasswordWhenOff(t *testing.T) {
	h := newHarness(t)
	n := h.register("nopw@example.com")
	page := bodyString(t, h.get("/u/"+strconv.Itoa(n)+"/passkeys"))
	if strings.Contains(page, "<h2>Password</h2>") || strings.Contains(page, `id="passwordForm"`) {
		t.Error("the passkeys page offers a password with PASSWORDS unset")
	}
	signin := bodyString(t, h.get("/signin?add=1"))
	if strings.Contains(signin, `id="chooseStep"`) || !strings.Contains(signin, "const PASSWORDS =  false ") {
		t.Error("the sign-in page offers a password with PASSWORDS unset")
	}
	if os.Getenv("NODE_CHECK") != "" {
		checkScripts(t, signin)
		checkScripts(t, page)
	}
}
