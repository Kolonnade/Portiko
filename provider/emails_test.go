package provider_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kolonnade/Portiko/internal/store"
	"github.com/Kolonnade/Portiko/provider"
)

type emailsReply struct {
	Account int `json:"account"`
	Emails  []struct {
		ID      int64  `json:"id"`
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
	Max         int    `json:"max"`
	ReauthUntil any    `json:"reauth_until"`
	HeldUntil   any    `json:"held_until"`
	Status      string `json:"status"`
	Error       string `json:"error"`
}

// emailCall is a browser's fetch to an email endpoint: JSON, same origin. It
// returns the raw body too, so two refusals can be compared byte for byte.
func (h *harness) emailCall(path string, body map[string]any) (int, emailsReply, string) {
	h.t.Helper()
	blob, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+h.prefix+"/accounts/v1/emails"+path, bytes.NewReader(blob))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", h.srv.URL)
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	raw := bodyString(h.t, resp)
	var out emailsReply
	_ = json.Unmarshal([]byte(raw), &out)
	return resp.StatusCode, out, raw
}

func (h *harness) listEmails(account int) emailsReply {
	h.t.Helper()
	resp := h.get("/accounts/v1/emails?account=" + strconv.Itoa(account))
	raw := bodyString(h.t, resp)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("list emails: %d %s", resp.StatusCode, raw)
	}
	var out emailsReply
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func (h *harness) pendingEmailCode(email string) string {
	h.t.Helper()
	var code string
	if err := h.db.Pool().QueryRow(context.Background(),
		`SELECT code FROM pending_emails WHERE email = $1 ORDER BY id DESC LIMIT 1`, store.NormalizeEmail(email)).Scan(&code); err != nil {
		h.t.Fatalf("reading the pending email code: %v", err)
	}
	return code
}

// addEmail adds an address to the account with its code, as the page does.
func (h *harness) addEmail(account int, email string) emailsReply {
	h.t.Helper()
	if status, _, raw := h.emailCall("/add", map[string]any{"account": account, "email": email}); status != http.StatusAccepted {
		h.t.Fatalf("emails/add %s: %d %s", email, status, raw)
	}
	status, out, raw := h.emailCall("/verify", map[string]any{"account": account, "email": email, "code": h.pendingEmailCode(email)})
	if status != http.StatusOK {
		h.t.Fatalf("emails/verify %s: %d %s", email, status, raw)
	}
	return out
}

// ageSessions makes every session's ceremony older than the re-auth window.
func (h *harness) ageSessions() {
	h.t.Helper()
	if _, err := h.db.Pool().Exec(context.Background(),
		`UPDATE sso_sessions SET authenticated_at = now() - interval '1 hour'`); err != nil {
		h.t.Fatal(err)
	}
}

func idOf(t *testing.T, r emailsReply, email string) int64 {
	t.Helper()
	for _, e := range r.Emails {
		if e.Email == email {
			return e.ID
		}
	}
	t.Fatalf("%s not in %+v", email, r.Emails)
	return 0
}

func changesTo(m *fakeMailer, change provider.EmailChange) []string {
	var to []string
	for _, c := range m.emailChanges() {
		if c.notice.Change == change {
			to = append(to, c.to)
		}
	}
	return to
}

func sameSet(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]int{}
	for _, g := range got {
		seen[g]++
	}
	for _, w := range want {
		if seen[w] == 0 {
			return false
		}
		seen[w]--
	}
	return true
}

func TestAddBackupEmailWithCode(t *testing.T) {
	h := newHarness(t)
	n := h.register("main@example.com")

	// A wrong code adds nothing.
	if status, _, _ := h.emailCall("/add", map[string]any{"account": n, "email": "Backup@Example.com"}); status != http.StatusAccepted {
		t.Fatalf("add: %d", status)
	}
	if status, _, _ := h.emailCall("/verify", map[string]any{"account": n, "email": "backup@example.com", "code": "000000x"}); status != http.StatusUnauthorized {
		t.Errorf("a wrong code: %d, want 401", status)
	}
	if got := h.listEmails(n); len(got.Emails) != 1 {
		t.Fatalf("a wrong code added an address: %+v", got.Emails)
	}

	out := h.addEmail(n, "Backup@Example.com")
	if len(out.Emails) != 2 || !out.Emails[0].Primary || out.Emails[0].Email != "main@example.com" ||
		out.Emails[1].Primary || out.Emails[1].Email != "backup@example.com" || out.Max != 3 {
		t.Fatalf("after adding: %+v", out)
	}
	if to := changesTo(h.mail, provider.EmailAdded); !sameSet(to, "main@example.com", "backup@example.com") {
		t.Errorf("added notices went to %v, want both addresses", to)
	}
	if rows := h.auditRows(store.AuditEmailAdded); len(rows) != 1 {
		t.Errorf("email.added rows: %d", len(rows))
	}

	// The backup signs in to the same account, and recovers it.
	resp := h.login("backup@example.com")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in by the backup address: %d %s", resp.StatusCode, bodyString(t, resp))
	}
	resp.Body.Close()
	if h.subjectOf("backup@example.com") != h.subjectOf("main@example.com") {
		t.Error("the backup address resolves to a different account")
	}
	if resp := h.post("/accounts/v1/register/start", map[string]string{"email": "backup@example.com"}); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("register/start: %d", resp.StatusCode)
	}
	var purpose string
	_ = h.db.Pool().QueryRow(context.Background(),
		`SELECT purpose FROM pending_registrations WHERE email = 'backup@example.com' ORDER BY id DESC LIMIT 1`).Scan(&purpose)
	if purpose != "recovery" {
		t.Errorf("a code to the backup address is for %q, want recovery of the account", purpose)
	}
}

func TestEmailLimit(t *testing.T) {
	h := newHarness(t)
	n := h.register("one@example.com")
	h.addEmail(n, "two@example.com")
	h.addEmail(n, "three@example.com")

	status, out, _ := h.emailCall("/add", map[string]any{"account": n, "email": "four@example.com"})
	if status != http.StatusConflict || out.Error != "email_limit_reached" {
		t.Errorf("a fourth address: %d %q, want 409 email_limit_reached", status, out.Error)
	}

	// A code issued before the limit was reached is refused at verify too.
	if err := h.db.CreatePendingEmail(context.Background(), mustUserID(t, h, "one@example.com"), "four@example.com", "123456", farFuture()); err != nil {
		t.Fatal(err)
	}
	status, out, _ = h.emailCall("/verify", map[string]any{"account": n, "email": "four@example.com", "code": "123456"})
	if status != http.StatusConflict || out.Error != "email_limit_reached" {
		t.Errorf("verify over the limit: %d %q", status, out.Error)
	}
}

// An address already on an account gets exactly the answers an unused address
// gets, so the endpoint cannot be used to find out who has an account.
func TestAddingATakenEmailIsIndistinguishable(t *testing.T) {
	h := newHarness(t)
	h.register("other@example.com")
	n := h.register("me@example.com")

	codesBefore := len(h.mail.codes)
	takenStatus, _, takenBody := h.emailCall("/add", map[string]any{"account": n, "email": "other@example.com"})
	freeStatus, _, freeBody := h.emailCall("/add", map[string]any{"account": n, "email": "free@example.com"})
	if takenStatus != freeStatus || takenBody != freeBody {
		t.Errorf("add answers differ: taken %d %s, free %d %s", takenStatus, takenBody, freeStatus, freeBody)
	}
	var pending int
	_ = h.db.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM pending_emails WHERE email = 'other@example.com'`).Scan(&pending)
	if pending != 0 {
		t.Error("a code was issued for an address already on an account")
	}
	for _, c := range h.mail.codes[codesBefore:] {
		if c == "other@example.com" {
			t.Error("a code was mailed to an address already on an account")
		}
	}

	takenStatus, _, takenBody = h.emailCall("/verify", map[string]any{"account": n, "email": "other@example.com", "code": "123456"})
	freeStatus, _, freeBody = h.emailCall("/verify", map[string]any{"account": n, "email": "free@example.com", "code": "badbad"})
	if takenStatus != http.StatusUnauthorized || takenStatus != freeStatus || takenBody != freeBody {
		t.Errorf("verify answers differ: taken %d %s, wrong code %d %s", takenStatus, takenBody, freeStatus, freeBody)
	}

	// Taken between the code and the verify: still the generic failure.
	if err := h.db.CreatePendingEmail(context.Background(), mustUserID(t, h, "me@example.com"), "other@example.com", "654321", farFuture()); err != nil {
		t.Fatal(err)
	}
	if status, _, body := h.emailCall("/verify", map[string]any{"account": n, "email": "other@example.com", "code": "654321"}); status != http.StatusUnauthorized || body != freeBody {
		t.Errorf("verifying an address taken meanwhile: %d %s", status, body)
	}
	if got := h.listEmails(n); len(got.Emails) != 1 {
		t.Errorf("the taken address was added: %+v", got.Emails)
	}
}

func TestChangingEmailsNeedsARecentPasskey(t *testing.T) {
	h := newHarness(t)
	n := h.register("re@example.com")
	backup := idOf(t, h.addEmail(n, "re2@example.com"), "re2@example.com")
	h.ageSessions()

	for _, c := range []struct {
		path string
		body map[string]any
	}{
		{"/add", map[string]any{"account": n, "email": "re3@example.com"}},
		{"/" + strconv.FormatInt(backup, 10) + "/primary", map[string]any{"account": n}},
		{"/" + strconv.FormatInt(backup, 10) + "/remove", map[string]any{"account": n}},
	} {
		status, out, _ := h.emailCall(c.path, c.body)
		if status != http.StatusForbidden || out.Error != "reauthentication_required" {
			t.Errorf("%s with an old ceremony: %d %q, want 403 reauthentication_required", c.path, status, out.Error)
		}
	}
	if got := h.listEmails(n); got.ReauthUntil != nil || len(got.Emails) != 2 || !got.Emails[0].Primary || got.Emails[0].Email != "re@example.com" {
		t.Fatalf("a refused change changed something: %+v", got)
	}

	// Signing in again as the account is the re-authentication.
	resp := h.login("re@example.com")
	resp.Body.Close()
	if got := h.listEmails(n); got.ReauthUntil == nil {
		t.Error("reauth_until is missing right after a ceremony")
	}
	if status, _, raw := h.emailCall("/"+strconv.FormatInt(backup, 10)+"/primary", map[string]any{"account": n}); status != http.StatusOK {
		t.Errorf("after signing in again: %d %s", status, raw)
	}
}

func TestMakePrimaryAndRemove(t *testing.T) {
	h := newHarness(t)
	n := h.register("first@example.com")
	out := h.addEmail(n, "second@example.com")
	first, second := idOf(t, out, "first@example.com"), idOf(t, out, "second@example.com")

	// The primary cannot be removed.
	status, res, _ := h.emailCall("/"+strconv.FormatInt(first, 10)+"/remove", map[string]any{"account": n})
	if status != http.StatusConflict || res.Error != "cannot_remove_primary_email" {
		t.Errorf("removing the primary: %d %q", status, res.Error)
	}

	status, res, raw := h.emailCall("/"+strconv.FormatInt(second, 10)+"/primary", map[string]any{"account": n})
	if status != http.StatusOK || !res.Emails[0].Primary || res.Emails[0].Email != "second@example.com" || res.Emails[1].Primary {
		t.Fatalf("make primary: %d %s", status, raw)
	}
	if to := changesTo(h.mail, provider.EmailPrimaryChanged); !sameSet(to, "first@example.com", "second@example.com") {
		t.Errorf("primary notices went to %v", to)
	}
	for _, c := range h.mail.emailChanges() {
		if c.notice.Change == provider.EmailPrimaryChanged && (c.notice.Address != "second@example.com" || c.notice.Previous != "first@example.com") {
			t.Errorf("primary notice: %+v", c.notice)
		}
	}
	// Making the primary primary again sends nothing more.
	before := len(h.mail.emailChanges())
	h.emailCall("/"+strconv.FormatInt(second, 10)+"/primary", map[string]any{"account": n})
	if len(h.mail.emailChanges()) != before {
		t.Error("a no-op primary change sent notices")
	}

	// Now the old primary is a backup and can go; it is told too.
	status, res, raw = h.emailCall("/"+strconv.FormatInt(first, 10)+"/remove", map[string]any{"account": n})
	if status != http.StatusOK || len(res.Emails) != 1 || res.Emails[0].Email != "second@example.com" {
		t.Fatalf("remove: %d %s", status, raw)
	}
	if to := changesTo(h.mail, provider.EmailRemoved); !sameSet(to, "first@example.com", "second@example.com") {
		t.Errorf("removed notices went to %v, want the remaining and the removed address", to)
	}
	if _, err := h.db.ByIdentifier(context.Background(), "email", "first@example.com"); err == nil {
		t.Error("the removed address still signs in")
	}
	if rows := h.auditRows(store.AuditEmailRemoved); len(rows) != 1 {
		t.Errorf("email.removed rows: %d", len(rows))
	}
	if rows := h.auditRows(store.AuditEmailPrimaryChanged); len(rows) != 1 {
		t.Errorf("email.primary_changed rows: %d", len(rows))
	}
}

// An address id on another account is not found, the same as one that does not
// exist.
func TestEmailIDsOfAnotherAccountAreNotFound(t *testing.T) {
	h := newHarness(t)
	theirs := h.register("theirs@example.com")
	theirBackup := idOf(t, h.addEmail(theirs, "theirs2@example.com"), "theirs2@example.com")
	mine := h.register("mine@example.com")

	for _, action := range []string{"primary", "remove"} {
		status, _, body := h.emailCall("/"+strconv.FormatInt(theirBackup, 10)+"/"+action, map[string]any{"account": mine})
		missing, _, missingBody := h.emailCall("/999999/"+action, map[string]any{"account": mine})
		if status != http.StatusNotFound || status != missing || body != missingBody {
			t.Errorf("%s on another account's address: %d %s; on none: %d %s", action, status, body, missing, missingBody)
		}
	}
	if got := h.listEmails(theirs); len(got.Emails) != 2 || got.Emails[0].Email != "theirs@example.com" {
		t.Errorf("the other account changed: %+v", got.Emails)
	}
}

// email in the id_token and userinfo is the primary, and follows a change at
// the next sign-in.
func TestEmailClaimFollowsThePrimary(t *testing.T) {
	h := newHarness(t)
	n := h.register("claim@example.com")
	backup := idOf(t, h.addEmail(n, "claim2@example.com"), "claim2@example.com")
	s := h.newSite("groups", func(c *store.Client) { c.AllowedScopes = append(c.AllowedScopes, "email") })

	signIn := func() (idEmail, infoEmail any) { return h.emailClaims(t, s, "openid email") }

	// A site not granted email gets it from neither.
	plain := h.newSite("plain")
	if id, info := h.emailClaims(t, plain, "openid profile"); id != nil || info != nil {
		t.Errorf("a site without the email scope got id_token %v, userinfo %v", id, info)
	}

	if id, info := signIn(); id != "claim@example.com" || info != "claim@example.com" {
		t.Fatalf("before: id_token %v, userinfo %v", id, info)
	}
	if status, _, raw := h.emailCall("/"+strconv.FormatInt(backup, 10)+"/primary", map[string]any{"account": n}); status != http.StatusOK {
		t.Fatalf("make primary: %d %s", status, raw)
	}
	if id, info := signIn(); id != "claim2@example.com" || info != "claim2@example.com" {
		t.Errorf("after: id_token %v, userinfo %v; want the new primary", id, info)
	}
}

// emailClaims signs in to s with scope and returns email from the ID token and
// from userinfo.
func (h *harness) emailClaims(t *testing.T, s *site, scope string) (idEmail, infoEmail any) {
	t.Helper()
	{
		cb, resp := h.authorize(s.clientID, s.url+"/auth/callback", scope, nil)
		if cb == nil {
			t.Fatalf("authorize did not return to the site: %d %s", resp.StatusCode, bodyString(t, resp))
		}
		out := h.redeemCode(s, cb.Query().Get("code"))
		c := claimsOf(t, out["id_token"].(string))
		if c["email"] != nil && c["email_verified"] != true {
			t.Errorf("email_verified = %v", c["email_verified"])
		}
		req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/oauth/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+out["access_token"].(string))
		ui, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var info map[string]any
		_ = json.NewDecoder(ui.Body).Decode(&info)
		ui.Body.Close()
		return c["email"], info["email"]
	}
}

func mustUserID(t *testing.T, h *harness, email string) int64 {
	t.Helper()
	u, err := h.db.ByIdentifier(context.Background(), "email", email)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func farFuture() time.Time { return time.Now().Add(time.Hour) }

// Each change is reported to the deployment's event hook, without the address.
func TestEmailChangesAreEvents(t *testing.T) {
	h := newHarness(t)
	n := h.register("ev@example.com")
	log := h.withEvents()
	backup := idOf(t, h.addEmail(n, "ev2@example.com"), "ev2@example.com")
	h.emailCall("/"+strconv.FormatInt(backup, 10)+"/primary", map[string]any{"account": n})
	first := idOf(t, h.listEmails(n), "ev@example.com")
	h.emailCall("/"+strconv.FormatInt(first, 10)+"/remove", map[string]any{"account": n})
	h.ageSessions()
	h.emailCall("/add", map[string]any{"account": n, "email": "ev3@example.com"})

	for _, stage := range []provider.SignInStage{provider.StageEmailAdded, provider.StageEmailPrimaryChanged, provider.StageEmailRemoved} {
		if log.find(stage, provider.OutcomeOK) == nil {
			t.Errorf("no ok %s event", stage)
		}
	}
	if e := log.find(provider.StageEmailAdded, provider.OutcomeFail); e == nil || e.Reason != "reauthentication_required" {
		t.Errorf("the refused addition: %+v", e)
	}
	for _, e := range log.all() {
		if blob, _ := json.Marshal(e); bytes.Contains(blob, []byte("@example.com")) {
			t.Errorf("an event carries an address: %s", blob)
		}
	}
}

func TestEmailsPage(t *testing.T) {
	h := newHarness(t)
	n := h.register("page@example.com")
	h.addEmail(n, "page2@example.com")

	resp := h.get("/u/" + strconv.Itoa(n) + "/emails")
	body := bodyString(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "page@example.com") ||
		!strings.Contains(body, "page2@example.com") || !strings.Contains(body, "Make primary") {
		t.Fatalf("emails page: %d %s", resp.StatusCode, body)
	}

	c := *h.client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r, err := c.Get(h.srv.URL + "/emails")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if loc := r.Header.Get("Location"); r.StatusCode != http.StatusFound || loc != "/u/"+strconv.Itoa(n)+"/emails" {
		t.Errorf("/emails: %d %q", r.StatusCode, loc)
	}
}
