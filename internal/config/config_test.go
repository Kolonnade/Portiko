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
