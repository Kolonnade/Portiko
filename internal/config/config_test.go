package config

import (
	"strings"
	"testing"
)

// An unset or mistyped mode must never resolve to open when a code is set,
// and an unknown value is closed rather than open.
func TestRegistrationModeFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		mode, code, want string
	}{
		{"", "", RegistrationOpen},
		{"", "a-long-bootstrap-code", RegistrationCode},
		{"open", "", RegistrationOpen},
		{"code", "a-long-bootstrap-code", RegistrationCode},
		{"closed", "a-long-bootstrap-code", RegistrationClosed},
		{"Open", "", RegistrationClosed},
		{"clsoed", "", RegistrationClosed},
	} {
		c := &Config{Registration: tc.mode, BootstrapCode: tc.code}
		if got := c.RegistrationMode(); got != tc.want {
			t.Errorf("REGISTRATION=%q BOOTSTRAP_CODE=%q: got %q, want %q", tc.mode, tc.code, got, tc.want)
		}
	}
}

func TestLoadRejectsInconsistentRegistration(t *testing.T) {
	for _, tc := range []struct {
		mode, code, want string
	}{
		{"code", "", "REGISTRATION=code needs BOOTSTRAP_CODE"},
		{"open", "a-long-bootstrap-code", "REGISTRATION=open ignores BOOTSTRAP_CODE"},
		{"sometimes", "", "REGISTRATION must be open, code or closed"},
		{"", "short", "BOOTSTRAP_CODE must be at least"},
	} {
		t.Setenv("REGISTRATION", tc.mode)
		t.Setenv("BOOTSTRAP_CODE", tc.code)
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("REGISTRATION=%q BOOTSTRAP_CODE=%q: got %v, want %q", tc.mode, tc.code, err, tc.want)
		}
	}
}

func TestLoadValidatesTheIssuerPath(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("WEBAUTHN_RP_ID", "example.com")
	t.Setenv("WEBAUTHN_RP_ORIGINS", "https://example.com")
	t.Setenv("CRYPTO_KEY", strings.Repeat("ab", 32))
	t.Setenv("REGISTRATION", "closed")
	t.Setenv("BOOTSTRAP_CODE", "")
	for issuer, base := range map[string]string{
		"https://example.com": "", "https://example.com/": "", "https://example.com/id": "/id",
		"https://example.com/id/": "/id", "https://example.com/a/b-c_d.e~f": "/a/b-c_d.e~f",
	} {
		t.Setenv("ISSUER", issuer)
		c, err := Load()
		if err != nil || c.BasePath() != base {
			t.Errorf("ISSUER=%q: base %q err %v, want %q", issuer, c.BasePath(), err, base)
		}
	}
	for _, issuer := range []string{
		"https://example.com/id//", "https://example.com//id", "https://example.com/a//b", "https://example.com/id?x=1",
		"https://example.com/id#f", "https://example.com/i%20d", "https://example.com/id%2Fx", "https://example.com/a/../b",
		"https://example.com/./id", "https://example.com/café",
	} {
		t.Setenv("ISSUER", issuer)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ISSUER") {
			t.Errorf("ISSUER=%q should be refused, got %v", issuer, err)
		}
	}
}
