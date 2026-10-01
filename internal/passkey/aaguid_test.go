package passkey

import "testing"

// The property that matters is the negative one: an AAGUID the table does not
// know must produce no name at all. The notice this feeds asks the holder "was
// this you?", and a guessed authenticator name is exactly what makes them answer
// yes to an enrollment that was not theirs.
func TestAuthenticatorNameNeverGuesses(t *testing.T) {
	icloud := ParseAAGUID("fbfc3007-154e-4ecc-8c0b-6e020557d7bd")
	for _, c := range []struct {
		name   string
		aaguid []byte
		want   string
	}{
		{"a known provider", icloud, "iCloud Keychain"},
		{"an unknown provider", ParseAAGUID("11111111-2222-3333-4444-555555555555"), ""},
		{"not reported", ParseAAGUID("00000000-0000-0000-0000-000000000000"), ""},
		{"absent", nil, ""},
		{"the wrong length", icloud[:8], ""},
	} {
		if got := AuthenticatorName(c.aaguid); got != c.want {
			t.Errorf("%s: AuthenticatorName = %q, want %q", c.name, got, c.want)
		}
	}
}
