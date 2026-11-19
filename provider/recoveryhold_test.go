package provider_test

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/Kolonnade/Portiko/internal/accounts"
)

func emailIDOf(t *testing.T, r emailsReply, email string) string {
	t.Helper()
	for _, e := range r.Emails {
		if e.Email == email {
			return strconv.FormatInt(e.ID, 10)
		}
	}
	t.Fatalf("%s is not on the account: %+v", email, r.Emails)
	return ""
}

func (h *harness) loginOK(email string) {
	h.t.Helper()
	resp := h.login(email)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("sign-in: %d %s", resp.StatusCode, bodyString(h.t, resp))
	}
	resp.Body.Close()
}

// Whoever reads one backup inbox can recover the account and enroll a passkey.
// That passkey must not be able to take the holder's addresses and passkeys
// away before the notices are read; a passkey the holder already had can.
func TestRecoveryHold(t *testing.T) {
	h := newHarness(t)
	n := h.register("owner@example.com")
	h.addEmail(n, "backup@example.com")
	original := h.listPasskeys(n)[0].ID

	// Recovery through the backup address, which enrolls a second passkey.
	if m := h.register("backup@example.com"); m != n {
		t.Fatalf("recovery signed in as account %d, want %d", m, n)
	}
	var until time.Time
	if err := h.db.Pool().QueryRow(context.Background(),
		`SELECT restricted_until FROM passkey_credentials ORDER BY id DESC LIMIT 1`).Scan(&until); err != nil {
		t.Fatalf("the recovered passkey has no hold: %v", err)
	}
	if d := time.Until(until); d < accounts.RecoveryHold-time.Minute || d > accounts.RecoveryHold {
		t.Errorf("hold ends in %v, want %v", d, accounts.RecoveryHold)
	}

	list := h.listEmails(n)
	if list.HeldUntil == nil {
		t.Error("the list does not say the session is held")
	}
	owner, backup := emailIDOf(t, list, "owner@example.com"), emailIDOf(t, list, "backup@example.com")
	if status, out, raw := h.emailCall("/"+backup+"/primary", map[string]any{"account": n}); status != http.StatusForbidden || out.Error != "recovery_hold" {
		t.Errorf("make primary while held: %d %s", status, raw)
	}
	if status, out, raw := h.emailCall("/"+owner+"/remove", map[string]any{"account": n}); status != http.StatusForbidden || out.Error != "recovery_hold" {
		t.Errorf("remove while held: %d %s", status, raw)
	}
	if status, out := h.postSameOrigin(passkeyPath(original, "revoke"), map[string]any{"account": n}); status != http.StatusForbidden || out.Error != "recovery_hold" {
		t.Errorf("revoke the holder's passkey while held: %d %+v", status, out)
	}
	// Adding an address takes nothing away, so it is not held.
	h.addEmail(n, "third@example.com")
	if got := h.listEmails(n); len(got.Emails) != 3 || !got.Emails[0].Primary || got.Emails[0].Email != "owner@example.com" {
		t.Fatalf("the held session changed the account: %+v", got.Emails)
	}
	if got := h.listPasskeys(n); len(got) != 2 {
		t.Fatalf("passkeys after the held revoke: %+v", got)
	}

	// The holder signs in with the passkey they had and undoes it.
	h.loginOK("owner@example.com")
	list = h.listEmails(n)
	if list.HeldUntil != nil {
		t.Fatalf("signing in with the original passkey left the hold: %v", list.HeldUntil)
	}
	if status, _, raw := h.emailCall("/"+emailIDOf(t, list, "third@example.com")+"/remove", map[string]any{"account": n}); status != http.StatusOK {
		t.Errorf("remove with the original passkey: %d %s", status, raw)
	}
	recovered := h.listPasskeys(n)[1].ID
	if status, out := h.postSameOrigin(passkeyPath(recovered, "revoke"), map[string]any{"account": n}); status != http.StatusOK {
		t.Errorf("revoke the recovered passkey: %d %+v", status, out)
	}
}

func TestRecoveryHoldEnds(t *testing.T) {
	h := newHarness(t)
	n := h.register("owner@example.com")
	h.addEmail(n, "backup@example.com")
	h.register("owner@example.com")
	if _, err := h.db.Pool().Exec(context.Background(),
		`UPDATE sso_sessions SET restricted_until = now() - interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	list := h.listEmails(n)
	if list.HeldUntil != nil {
		t.Errorf("a past hold is reported: %v", list.HeldUntil)
	}
	if status, _, raw := h.emailCall("/"+emailIDOf(t, list, "backup@example.com")+"/primary", map[string]any{"account": n}); status != http.StatusOK {
		t.Errorf("make primary after the hold: %d %s", status, raw)
	}
}

// A session cookie alone must not remove a passkey: that would let a stolen
// cookie take the holder's way back in.
func TestRevokePasskeyNeedsRecentSignIn(t *testing.T) {
	h := newHarness(t)
	n := h.register("keys@example.com")
	second := h.addPasskey("keys@example.com", "Spare", "")
	h.ageSessions()
	if status, out := h.postSameOrigin(passkeyPath(second, "revoke"), map[string]any{"account": n}); status != http.StatusForbidden || out.Error != "reauthentication_required" {
		t.Fatalf("revoke with an old sign-in: %d %+v", status, out)
	}
	if got := h.listPasskeys(n); len(got) != 2 {
		t.Fatalf("a refused revoke removed a passkey: %+v", got)
	}
	h.loginOK("keys@example.com")
	if status, out := h.postSameOrigin(passkeyPath(second, "revoke"), map[string]any{"account": n}); status != http.StatusOK {
		t.Errorf("revoke after signing in again: %d %+v", status, out)
	}
}
