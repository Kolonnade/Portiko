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

func TestReservedTestDomain(t *testing.T) {
	for _, d := range []string{"example.test", "a.b.test", "x.invalid", "foo.example", "example.com", "mail.example.org"} {
		if !ReservedTestDomain(d) {
			t.Errorf("%q should be reserved", d)
		}
	}
	for _, d := range []string{"gmail.com", "test.com", "example.co", "notexample.com", "localhost", "*.test", ".test", "a..test", ""} {
		if ReservedTestDomain(d) {
			t.Errorf("%q should not be reserved", d)
		}
	}
}

func TestLoadTestMailDomains(t *testing.T) {
	t.Setenv("ISSUER", "https://example.com")
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("WEBAUTHN_RP_ID", "example.com")
	t.Setenv("WEBAUTHN_RP_ORIGINS", "https://example.com")
	t.Setenv("CRYPTO_KEY", strings.Repeat("ab", 32))
	t.Setenv("REGISTRATION", "closed")
	t.Setenv("BOOTSTRAP_CODE", "")

	t.Setenv("TEST_MAIL_DOMAINS", " Example.TEST , example.com")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := strings.Join(c.TestMailDomains, ","); got != "example.test,example.com" {
		t.Errorf("TestMailDomains = %q", got)
	}

	t.Setenv("TEST_MAIL_DOMAINS", "example.test,gmail.com")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "gmail.com") {
		t.Errorf("a real domain must stop Load, got %v", err)
	}

	t.Setenv("TEST_MAIL_DOMAINS", "")
	c, err = Load()
	if err != nil || c.TestMailDomains != nil {
		t.Errorf("unset: %v, %v", c, err)
	}
}

func TestLoadRateLimitExempt(t *testing.T) {
	t.Setenv("ISSUER", "https://example.com")
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("WEBAUTHN_RP_ID", "example.com")
	t.Setenv("WEBAUTHN_RP_ORIGINS", "https://example.com")
	t.Setenv("CRYPTO_KEY", strings.Repeat("ab", 32))
	t.Setenv("REGISTRATION", "closed")
	t.Setenv("BOOTSTRAP_CODE", "")

	t.Setenv("RATE_LIMIT_EXEMPT", "")
	c, err := Load()
	if err != nil || c.RateLimitExempt != nil {
		t.Fatalf("unset: %v, %v", c, err)
	}

	t.Setenv("RATE_LIMIT_EXEMPT", " 198.51.100.7 , 10.1.2.3/8, 2001:db8::/32")
	c, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var got []string
	for _, p := range c.RateLimitExempt {
		got = append(got, p.String())
	}
	if strings.Join(got, ",") != "198.51.100.7/32,10.0.0.0/8,2001:db8::/32" {
		t.Errorf("RateLimitExempt = %v", got)
	}

	for _, bad := range []string{"0.0.0.0/0", "::/0", "not-an-ip"} {
		t.Setenv("RATE_LIMIT_EXEMPT", "198.51.100.7,"+bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "RATE_LIMIT_EXEMPT") {
			t.Errorf("%q must stop Load, got %v", bad, err)
		}
	}
}

func TestLoadMaxEmails(t *testing.T) {
	t.Setenv("ISSUER", "https://example.com")
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("WEBAUTHN_RP_ID", "example.com")
	t.Setenv("WEBAUTHN_RP_ORIGINS", "https://example.com")
	t.Setenv("CRYPTO_KEY", strings.Repeat("ab", 32))
	t.Setenv("REGISTRATION", "closed")
	t.Setenv("BOOTSTRAP_CODE", "")

	t.Setenv("MAX_EMAILS", "")
	c, err := Load()
	if err != nil || c.EmailLimit() != DefaultMaxEmails {
		t.Fatalf("unset: %v, %v", c, err)
	}
	if (&Config{}).EmailLimit() != DefaultMaxEmails {
		t.Error("a hand-built Config should get the default")
	}
	t.Setenv("MAX_EMAILS", "5")
	if c, err := Load(); err != nil || c.EmailLimit() != 5 {
		t.Errorf("5: %v, %v", c, err)
	}
	for _, bad := range []string{"0", "11", "-1", "three"} {
		t.Setenv("MAX_EMAILS", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MAX_EMAILS") {
			t.Errorf("%q must stop Load, got %v", bad, err)
		}
	}
}

// Passwords are off unless a deployment says allow; anything else stops Load,
// and a hand-built Config with an unknown value is off.
func TestLoadPasswords(t *testing.T) {
	t.Setenv("ISSUER", "https://example.com")
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("WEBAUTHN_RP_ID", "example.com")
	t.Setenv("WEBAUTHN_RP_ORIGINS", "https://example.com")
	t.Setenv("CRYPTO_KEY", strings.Repeat("ab", 32))
	t.Setenv("REGISTRATION", "closed")
	t.Setenv("BOOTSTRAP_CODE", "")

	for v, want := range map[string]bool{"": false, "off": false, "allow": true, "Allow": true, " allow ": true} {
		t.Setenv("PASSWORDS", v)
		c, err := Load()
		if err != nil || c.PasswordsAllowed() != want {
			t.Errorf("PASSWORDS=%q: allowed %v err %v, want %v", v, c != nil && c.PasswordsAllowed(), err, want)
		}
	}
	for _, bad := range []string{"on", "true", "yes", "1"} {
		t.Setenv("PASSWORDS", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PASSWORDS") {
			t.Errorf("PASSWORDS=%q must stop Load, got %v", bad, err)
		}
	}
	if (&Config{}).PasswordsAllowed() || (&Config{Passwords: "on"}).PasswordsAllowed() {
		t.Error("a hand-built Config must not allow passwords unless it says allow")
	}
}
