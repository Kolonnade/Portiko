package localpath

import "testing"

func TestIs(t *testing.T) {
	for _, p := range []string{"/", "/profile", "/u/0/", "/id/signin?return_to=%2Fx", "/a/b#frag", "/caf%C3%A9"} {
		if !Is(p) {
			t.Errorf("%q should be a local path", p)
		}
	}
	// What a browser turns into another site, or is not a path at all. The
	// query-decoded forms are what a handler sees: /%5Cevil arrives as /\evil.
	for _, p := range []string{
		"", "profile", "//evil.example", "/\\evil.example", "/\\/evil.example", "\\\\evil.example",
		"/\t/evil.example", "/\n/evil.example", "/\r/evil.example", "/\x00x", "/\x7fx",
		"https://evil.example", "http:/evil.example", "javascript:alert(1)", "/x\\y",
	} {
		if Is(p) {
			t.Errorf("%q must be refused", p)
		}
	}
	if !Is("/%5C") {
		t.Error("an encoded backslash that was never decoded is just a path")
	}
}

func TestOr(t *testing.T) {
	if Or("/\\evil.example", "/") != "/" || Or("/profile", "/") != "/profile" {
		t.Error("Or")
	}
}
