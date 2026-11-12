package provider_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kolonnade/Portiko/internal/passkey"
	"github.com/Kolonnade/Portiko/internal/store"
)

// iCloudAAGUID is in the provider-hint table.
const iCloudAAGUID = "fbfc3007-154e-4ecc-8c0b-6e020557d7bd"

type passkeyJSON struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Provider   string     `json:"provider"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

type passkeysReply struct {
	Account  int           `json:"account"`
	Passkeys []passkeyJSON `json:"passkeys"`
	Signal   *struct {
		RPID  string `json:"rp_id"`
		Users []struct {
			UserID        string   `json:"user_id"`
			CredentialIDs []string `json:"credential_ids"`
		} `json:"users"`
	} `json:"signal"`
	Error string `json:"error"`
}

// postSameOrigin is a browser's fetch: JSON, with this provider's own Origin.
func (h *harness) postSameOrigin(path string, body any) (int, passkeysReply) {
	h.t.Helper()
	blob, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+h.prefix+path, bytes.NewReader(blob))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", h.srv.URL)
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out passkeysReply
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (h *harness) listPasskeys(account int) []passkeyJSON {
	h.t.Helper()
	resp := h.get("/accounts/v1/passkeys?account=" + strconv.Itoa(account))
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("list passkeys: %d %s", resp.StatusCode, bodyString(h.t, resp))
	}
	var out passkeysReply
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	return out.Passkeys
}

// addPasskey enrolls a second credential straight into the store, with an
// AAGUID the provider can name.
func (h *harness) addPasskey(email, name, aaguid string) int64 {
	h.t.Helper()
	ctx := context.Background()
	u, err := h.db.ByIdentifier(ctx, "email", email)
	if err != nil {
		h.t.Fatal(err)
	}
	existing, err := h.db.ByUser(ctx, u.ID)
	if err != nil || len(existing) == 0 {
		h.t.Fatalf("existing credentials: %v", err)
	}
	id := uuid.New()
	if err := h.db.Insert(ctx, passkey.StoredCredential{
		UserID: u.ID, CredentialID: id[:], PublicKey: []byte("pk"), UserHandle: existing[0].UserHandle,
		AAGUID: passkey.ParseAAGUID(aaguid), DeviceName: name, BackupEligible: true, BackupState: true, RPID: "localhost",
	}); err != nil {
		h.t.Fatal(err)
	}
	all, _ := h.db.ListManaged(ctx, u.ID)
	for _, c := range all {
		if c.Name == name {
			return c.ID
		}
	}
	h.t.Fatal("added passkey not found")
	return 0
}

func expectStatus(t *testing.T, h *harness, req *http.Request, want int, what string) {
	t.Helper()
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	resp.Body.Close()
	if resp.StatusCode != want {
		t.Errorf("%s: %d, want %d", what, resp.StatusCode, want)
	}
}

func passkeyPath(id int64, action string) string {
	return "/accounts/v1/passkeys/" + strconv.FormatInt(id, 10) + "/" + action
}

func TestPasskeysListRenameRevoke(t *testing.T) {
	for _, prefix := range []string{"", "/id"} {
		t.Run("prefix="+prefix, func(t *testing.T) {
			h := newHarnessAt(t, prefix)
			h.register("keys@example.com")

			list := h.listPasskeys(0)
			if len(list) != 1 || list[0].CreatedAt.IsZero() || list[0].LastUsedAt != nil {
				t.Fatalf("a new account's passkeys = %+v", list)
			}
			first := list[0].ID
			second := h.addPasskey("keys@example.com", "Laptop", iCloudAAGUID)
			if err := h.db.RecordLogin(context.Background(), mustCredentialID(t, h, second), 1, true); err != nil {
				t.Fatal(err)
			}

			list = h.listPasskeys(0)
			if len(list) != 2 {
				t.Fatalf("passkeys = %+v", list)
			}
			if got := list[1]; got.Name != "Laptop" || got.Provider != "iCloud Keychain" || got.LastUsedAt == nil {
				t.Errorf("second passkey = %+v, want a named iCloud Keychain passkey with a last-used time", got)
			}
			if list[0].Provider != "Unknown" {
				t.Errorf("a passkey with no AAGUID has provider %q", list[0].Provider)
			}

			// Rename.
			code, out := h.postSameOrigin(passkeyPath(second, "rename"), map[string]any{"account": 0, "name": "  Work Mac "})
			if code != http.StatusOK || out.Passkeys[1].Name != "Work Mac" || out.Signal != nil {
				t.Fatalf("rename: %d %+v", code, out)
			}
			if code, _ := h.postSameOrigin(passkeyPath(second, "rename"), map[string]any{"account": 0, "name": " "}); code != http.StatusBadRequest {
				t.Errorf("empty name: %d, want 400", code)
			}
			if code, _ := h.postSameOrigin(passkeyPath(second, "rename"), map[string]any{"account": 0, "name": "Work Mac"}); code != http.StatusOK {
				t.Errorf("renaming to the current name: %d", code)
			}
			rows := h.auditRows("credential.renamed")
			if len(rows) != 1 || !strings.Contains(rows[0].detail, `"Work Mac"`) || !strings.Contains(rows[0].detail, `"Laptop"`) || rows[0].userAgent == "" {
				t.Fatalf("rename audit rows = %+v", rows)
			}

			// Revoke one of two: allowed, and the response says what to signal.
			code, out = h.postSameOrigin(passkeyPath(second, "revoke"), map[string]any{"account": 0})
			if code != http.StatusOK || len(out.Passkeys) != 1 || out.Passkeys[0].ID != first {
				t.Fatalf("revoke: %d %+v", code, out)
			}
			if out.Signal == nil || out.Signal.RPID != "localhost" || len(out.Signal.Users) != 1 || len(out.Signal.Users[0].CredentialIDs) != 1 {
				t.Errorf("revoke signal = %+v, want the one remaining credential for the user handle", out.Signal)
			}
			rows = h.auditRows("credential.revoked")
			if len(rows) != 1 || !strings.Contains(rows[0].detail, `"Work Mac"`) || !strings.Contains(rows[0].detail, "iCloud Keychain") {
				t.Fatalf("revoke audit rows = %+v", rows)
			}

			// The last one is refused, and stays.
			code, out = h.postSameOrigin(passkeyPath(first, "revoke"), map[string]any{"account": 0})
			if code != http.StatusConflict || out.Error != "cannot_revoke_last_passkey" {
				t.Fatalf("revoking the last passkey: %d %+v", code, out)
			}
			if len(h.listPasskeys(0)) != 1 || len(h.auditRows("credential.revoked")) != 1 {
				t.Error("the refused revoke changed something")
			}
			// And the person can still sign in with it.
			if r := h.login("keys@example.com"); r.StatusCode != http.StatusOK {
				t.Errorf("sign-in after the refused revoke: %d", r.StatusCode)
			}
		})
	}
}

func mustCredentialID(t *testing.T, h *harness, id int64) []byte {
	t.Helper()
	var raw []byte
	if err := h.db.Pool().QueryRow(context.Background(),
		`SELECT credential_id FROM passkey_credentials WHERE id = $1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

// Another account's passkey is "not found", whether or not it exists, and
// nothing about it changes. The 404 also wins over the last-passkey refusal:
// the caller holds one passkey, and a 409 would confirm the id was real.
func TestPasskeyOfAnotherAccountIsNotFound(t *testing.T) {
	h := newHarness(t)
	h.register("mine@example.com")
	h.register("theirs@example.com")
	theirs := h.listPasskeys(1)[0].ID
	other := h.addPasskey("theirs@example.com", "Theirs Two", iCloudAAGUID)

	for _, id := range []int64{theirs, other, 999999} {
		code, out := h.postSameOrigin(passkeyPath(id, "rename"), map[string]any{"account": 0, "name": "Hijacked"})
		if code != http.StatusNotFound || out.Error != "not_found" {
			t.Errorf("rename %d: %d %+v", id, code, out)
		}
		code, out = h.postSameOrigin(passkeyPath(id, "revoke"), map[string]any{"account": 0})
		if code != http.StatusNotFound || out.Error != "not_found" {
			t.Errorf("revoke %d: %d %+v", id, code, out)
		}
	}
	if code, _ := h.postSameOrigin("/accounts/v1/passkeys/abc/revoke", map[string]any{"account": 0}); code != http.StatusNotFound {
		t.Errorf("a non-numeric id: %d", code)
	}
	list := h.listPasskeys(1)
	if len(list) != 2 || list[0].Name == "Hijacked" || list[1].Name != "Theirs Two" {
		t.Errorf("the other account's passkeys changed: %+v", list)
	}
	if n := len(h.auditRows("credential.renamed")) + len(h.auditRows("credential.revoked")); n != 0 {
		t.Errorf("%d audit rows written for refused requests", n)
	}
}

func TestPasskeyEndpointsRequireASessionAndTheSameOrigin(t *testing.T) {
	h := newHarness(t)
	if r := h.get("/accounts/v1/passkeys?account=0"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("signed out list: %d", r.StatusCode)
	}
	h.register("guard@example.com")
	h.addPasskey("guard@example.com", "Two", iCloudAAGUID)
	id := h.listPasskeys(0)[1].ID

	if r := h.post(passkeyPath(id, "revoke"), map[string]any{"account": 0}); r.StatusCode != http.StatusForbidden {
		t.Errorf("no Origin: %d, want 403", r.StatusCode)
	}
	blob, _ := json.Marshal(map[string]any{"account": 0})
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+passkeyPath(id, "revoke"), bytes.NewReader(blob))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	expectStatus(t, h, req, http.StatusForbidden, "cross-origin revoke")
	req, _ = http.NewRequest(http.MethodPost, h.srv.URL+passkeyPath(id, "revoke"), strings.NewReader("account=0"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", h.srv.URL)
	expectStatus(t, h, req, http.StatusUnsupportedMediaType, "form revoke")
	if code, _ := h.postSameOrigin(passkeyPath(id, "revoke"), map[string]any{}); code != http.StatusBadRequest {
		t.Errorf("revoke without an account: %d, want 400", code)
	}
	if code, _ := h.postSameOrigin(passkeyPath(id, "rename"), map[string]any{"name": "X"}); code != http.StatusBadRequest {
		t.Errorf("rename without an account: %d, want 400", code)
	}
	if code, _ := h.postSameOrigin(passkeyPath(id, "revoke"), map[string]any{"account": 7}); code != http.StatusUnauthorized {
		t.Errorf("an account this browser does not hold: %d", code)
	}
	if len(h.listPasskeys(0)) != 2 {
		t.Error("a refused request revoked something")
	}
}

// Two revokes of an account's last two passkeys at once: exactly one wins.
func TestConcurrentRevokesLeaveOnePasskey(t *testing.T) {
	h := newHarness(t)
	h.register("race@example.com")
	a := h.listPasskeys(0)[0].ID
	b := h.addPasskey("race@example.com", "Two", iCloudAAGUID)

	codes := make([]int, 2)
	var wg sync.WaitGroup
	for i, id := range []int64{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i], _ = h.postSameOrigin(passkeyPath(id, "revoke"), map[string]any{"account": 0})
		}()
	}
	wg.Wait()
	if ok, conflict := count(codes, 200), count(codes, 409); ok != 1 || conflict != 1 {
		t.Fatalf("revoke statuses = %v, want one 200 and one 409", codes)
	}
	if n := len(h.listPasskeys(0)); n != 1 {
		t.Fatalf("%d passkeys left, want 1", n)
	}
}

// Deterministic check that Revoke locks the account's credential rows: with
// another transaction holding them, Revoke must wait, and when that
// transaction has deleted one of two, Revoke sees one left and refuses.
func TestRevokeWaitsForTheAccountsCredentialLock(t *testing.T) {
	h := newHarness(t)
	h.register("lock@example.com")
	a := h.listPasskeys(0)[0].ID
	b := h.addPasskey("lock@example.com", "Two", iCloudAAGUID)
	u, err := h.db.ByIdentifier(context.Background(), "email", "lock@example.com")
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT id FROM passkey_credentials WHERE user_id = $1 FOR UPDATE`, u.ID); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { _, err := h.db.Revoke(ctx, u.ID, a); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("Revoke returned (%v) while another transaction held the credential rows", err)
	case <-time.After(300 * time.Millisecond):
	}

	if _, err := tx.Exec(ctx, `DELETE FROM passkey_credentials WHERE id = $1`, b); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, store.ErrLastCredential) {
			t.Fatalf("Revoke = %v, want ErrLastCredential", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Revoke never finished after the lock was released")
	}
	if n := len(h.listPasskeys(0)); n != 1 {
		t.Fatalf("%d passkeys left, want 1", n)
	}
}

func count(codes []int, want int) (n int) {
	for _, c := range codes {
		if c == want {
			n++
		}
	}
	return n
}

// The page and the pages that link to it hold the path prefix in every link,
// form action and fetch URL.
func TestPasskeysPageRendersUnderEachPrefix(t *testing.T) {
	for _, prefix := range []string{"", "/id"} {
		t.Run("prefix="+prefix, func(t *testing.T) {
			h := newHarnessAt(t, prefix)
			h.register("page@example.com")
			h.addPasskey("page@example.com", "Phone <b>", iCloudAAGUID)

			// html/template writes a slash inside a script string as \/.
			page := strings.ReplaceAll(bodyString(t, h.get("/u/0/passkeys")), `\/`, "/")
			for _, want := range []string{
				`href="` + prefix + `/u/0/"`,
				`const BASE = '` + prefix + `/accounts/v1/passkeys'`,
				`location.replace('` + prefix + `/')`,
				`Phone &lt;b&gt;`, "iCloud Keychain", "never used", "signalAcceptedPasskeys",
			} {
				if !strings.Contains(page, want) {
					t.Errorf("passkeys page lacks %q", want)
				}
			}
			if strings.Contains(page, "Phone <b>") {
				t.Error("a passkey name is not escaped")
			}
			if prefix != "" {
				for _, bad := range []string{`'/accounts/`, `"/u/`, `('/')`} {
					if strings.Contains(page, bad) {
						t.Errorf("passkeys page has an unprefixed %s", bad)
					}
				}
			}
			for _, from := range []string{"/u/0/", "/u/0/profile"} {
				if p := bodyString(t, h.get(from)); !strings.Contains(p, `href="`+prefix+`/u/0/passkeys"`) {
					t.Errorf("%s does not link to the passkeys page under %q", from, prefix)
				}
			}
			noFollow := &http.Client{Jar: h.client.Jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			resp, err := noFollow.Get(h.srv.URL + prefix + "/passkeys")
			if err != nil || resp.Header.Get("Location") != prefix+"/u/0/passkeys" {
				t.Errorf("GET /passkeys: %v %v", err, resp)
			}
			if r := h.get("/u/5/passkeys"); r.StatusCode != http.StatusNotFound {
				t.Errorf("an account this browser does not hold: %d", r.StatusCode)
			}
			if prefix == "" {
				if os.Getenv("NODE_CHECK") != "" {
					checkScripts(t, page)
				}
			}
		})
	}
}
