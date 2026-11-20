package password

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckLength(t *testing.T) {
	if err := Check("fourteen chars"); !errors.Is(err, ErrTooShort) {
		t.Errorf("14 characters: got %v, want ErrTooShort", err)
	}
	if err := Check("my cat likes hay"); err != nil {
		t.Errorf("16 ordinary characters with spaces should pass, got %v", err)
	}
	// Characters, not bytes: fifteen accented letters are fifteen characters.
	if err := Check(strings.Repeat("é", 14)); !errors.Is(err, ErrTooShort) {
		t.Errorf("14 two-byte characters: got %v, want ErrTooShort", err)
	}
	if err := Check(strings.Repeat("ab cd ef gh ij ", 80)); !errors.Is(err, ErrTooLong) {
		t.Errorf("1200 bytes: got %v, want ErrTooLong", err)
	}
	if err := Check("plenty of words in a row here, sixty-four characters long ok"); err != nil {
		t.Errorf("a long phrase must pass, got %v", err)
	}
}

// No composition rules: lowercase letters and spaces alone are fine.
func TestCheckHasNoCompositionRules(t *testing.T) {
	for _, pw := range []string{"purple elephants dance", "tuesdaymarmaladeorbit", "ПРИВЕТ МИР КАК ДЕЛА"} {
		if err := Check(pw); err != nil {
			t.Errorf("%q: %v", pw, err)
		}
	}
}

func TestCheckRefusesCommonAndPatterned(t *testing.T) {
	for _, pw := range []string{
		"123456789012345", "Password12345678", "Correct Horse Battery Staple",
		"correct-horse-battery-staple!", "passwordpassword", "aaaaaaaaaaaaaaa",
		"abcabcabcabcabc", "abcdefghijklmnop", "1234567890123456789", "9876543210987654",
		"qwertyuiopasdfgh", "QWERTYUIOPASDFGHJ", "1qaz2wsx3edc4rfv", "zyxwvutsrqponmlk",
		"!!!!!!!!!!!!!!!!",
	} {
		if err := Check(pw); !errors.Is(err, ErrCommon) {
			t.Errorf("%q: got %v, want ErrCommon", pw, err)
		}
	}
}

func TestCheckRefusesTheAccountsOwnWords(t *testing.T) {
	ctx := []string{"Alice.Smith@example.com", "Family Accounts"}
	for _, pw := range []string{"alice.smith@example.com", "AliceSmith111111", "familyaccounts!!", "alicesmithalicesmith"} {
		if err := Check(pw, ctx...); !errors.Is(err, ErrCommon) {
			t.Errorf("%q: got %v, want ErrCommon", pw, err)
		}
	}
	if err := Check("alice likes long walks", ctx...); err != nil {
		t.Errorf("a phrase that merely mentions the name must pass, got %v", err)
	}
}

func TestHashAndVerify(t *testing.T) {
	h, err := Hash("purple elephants dance")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("hash %q is not argon2id in PHC form with the expected parameters", h)
	}
	if ok, err := Verify("purple elephants dance", h); !ok || err != nil {
		t.Errorf("the right password: %v %v", ok, err)
	}
	if ok, _ := Verify("purple elephants dancE", h); ok {
		t.Error("a different password matched")
	}
	h2, _ := Hash("purple elephants dance")
	if h2 == h {
		t.Error("two hashes of one password are equal; the salt is not random")
	}
	if NeedsRehash(h) {
		t.Error("a fresh hash should not need rehashing")
	}
	old := strings.Replace(h, "m=19456,t=2", "m=8192,t=2", 1)
	if !NeedsRehash(old) {
		t.Error("a hash with other parameters should need rehashing")
	}
}

// NFKC: the same characters typed two ways are the same password.
func TestVerifyNormalizes(t *testing.T) {
	composed := "café au lait du matin"
	decomposed := "café au lait du matin"
	h, _ := Hash(composed)
	if ok, _ := Verify(decomposed, h); !ok {
		t.Error("a decomposed é did not match a composed one")
	}
}

func TestVerifyRefusesMalformedHashes(t *testing.T) {
	for _, h := range []string{"", "plain", "$argon2i$v=19$m=1,t=1,p=1$AA$AA", "$argon2id$v=19$m=99999999,t=1,p=1$AAAA$AAAA",
		"$argon2id$v=19$m=1024,t=1,p=1$!!$AAAA", "$2a$10$abcdefghijklmnopqrstuv"} {
		if ok, err := Verify("anything at all here", h); ok || err == nil {
			t.Errorf("%q: ok=%v err=%v, want an error and no match", h, ok, err)
		}
	}
}

func TestDecoyNeverPanics(t *testing.T) {
	Decoy("")
	Decoy("anything")
}
