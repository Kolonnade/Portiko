package provider_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
)

// signInWith runs login/start and login/finish with one given credential.
func (h *harness) signInWith(cred virtualwebauthn.Credential) (int, map[string]string) {
	h.t.Helper()
	resp := h.get("/accounts/v1/login/start")
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	options, err := virtualwebauthn.ParseAssertionOptions(string(raw))
	if err != nil {
		h.t.Fatalf("parsing assertion options: %v", err)
	}
	assertion := virtualwebauthn.CreateAssertionResponse(h.rp, h.auth, cred, *options)
	fin, err := h.client.Post(h.srv.URL+h.prefix+"/accounts/v1/login/finish", "application/json", strings.NewReader(assertion))
	if err != nil {
		h.t.Fatal(err)
	}
	defer fin.Body.Close()
	var out map[string]string
	_ = json.NewDecoder(fin.Body).Decode(&out)
	return fin.StatusCode, out
}

// A passkey the provider has no record of — removed, or never registered here
// — gets its own answer, so the page can tell the passkey provider to forget
// it; and the two cases are the same answer.
func TestUnknownCredential(t *testing.T) {
	h := newHarness(t)
	h.register("gone@example.com")
	removed := h.auth.Credentials[0]
	h.execSQL(`DELETE FROM passkey_credentials`)

	stranger := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	for name, cred := range map[string]virtualwebauthn.Credential{"removed": removed, "never registered": stranger} {
		status, out := h.signInWith(cred)
		if status != http.StatusUnauthorized || out["error"] != "unknown_credential" {
			t.Errorf("%s: %d %v", name, status, out)
			continue
		}
		if want := base64.RawURLEncoding.EncodeToString(cred.ID); out["credential_id"] != want {
			t.Errorf("%s: credential_id %q, want %q", name, out["credential_id"], want)
		}
		if out["rp_id"] != "localhost" || len(out) != 3 {
			t.Errorf("%s: answer %v", name, out)
		}
	}
}

// Any other failure is still the one generic answer.
func TestKnownCredentialFailureStaysGeneric(t *testing.T) {
	h := newHarness(t)
	h.register("known@example.com")
	// A disabled account's passkey is known: it must not read as unknown.
	h.execSQL(`UPDATE users SET active = FALSE`)
	status, out := h.signInWith(h.auth.Credentials[0])
	if status != http.StatusUnauthorized || out["error"] != "authentication_failed" {
		t.Errorf("disabled account: %d %v", status, out)
	}
}
