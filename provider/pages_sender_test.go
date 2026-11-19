package provider

import "testing"

func TestCodeSender(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"noreply@example.com", "noreply@example.com"},
		{"Example Service <noreply@example.com>", "noreply@example.com"},
		{"", ""},
		{"not an address", ""},
	} {
		if got := codeSender(tc.in); got != tc.want {
			t.Errorf("codeSender(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
