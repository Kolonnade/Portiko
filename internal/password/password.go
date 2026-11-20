// Package password is the opt-in password credential: hashing with Argon2id and
// the policy a new password has to meet.
//
// Passwords are off unless a deployment turns them on (PASSWORDS=allow), and
// passkeys stay the recommended credential. A password exists for the person
// whose device cannot use a passkey at all (docs/opinions.md).
//
// The policy is NIST SP 800-63B's for a single-factor password: a minimum
// length, no composition rules, and a check against values that are known to be
// guessed first. The check is local: a password is never sent anywhere to be
// looked up.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// MinLength is the fewest characters a password may have. Fifteen is NIST's
// minimum for a password that is the only factor, which here it always is.
const MinLength = 15

// MaxBytes bounds a password's length in bytes, after normalization. NIST asks
// for at least 64 characters to be accepted; the bound exists so that hashing
// cannot be made expensive with a megabyte of input.
const MaxBytes = 1024

// Argon2id parameters for new hashes: OWASP's recommended minimum (19 MiB, two
// passes, one lane). A deployment serving households sees a handful of password
// sign-ins an hour, so the cost is felt only by somebody guessing offline.
// Every hash records the parameters it was made with, so raising these later
// rehashes each password at its next sign-in (NeedsRehash).
const (
	memoryKiB = 19 * 1024
	passes    = 2
	lanes     = 1
	keyLen    = 32
	saltLen   = 16
)

// Policy failures. Each says what to do, so it can be shown as it is.
var (
	ErrTooShort = fmt.Errorf("use at least %d characters; a few ordinary words with spaces between them is fine", MinLength)
	ErrTooLong  = fmt.Errorf("use at most %d bytes", MaxBytes)
	ErrCommon   = errors.New("that password is too easy to guess; choose something less common")
)

// Normalize puts a password in the form it is hashed in: Unicode NFKC, as NIST
// asks, so the same characters typed on two keyboards are the same password.
func Normalize(pw string) string { return norm.NFKC.String(pw) }

// Check reports whether pw may be set, or the reason it may not. context lists
// values specific to this account and service (the email address, the service
// name) that must not be the password either.
//
// There are no composition rules: no required digits or symbols, no ban on
// spaces. They make passwords harder to remember and barely harder to guess.
func Check(pw string, context ...string) error {
	pw = Normalize(pw)
	if !utf8.ValidString(pw) || utf8.RuneCountInString(pw) < MinLength {
		return ErrTooShort
	}
	if len(pw) > MaxBytes {
		return ErrTooLong
	}
	folded := fold(pw)
	if folded == "" || common[folded] || common[strings.ToLower(pw)] {
		return ErrCommon
	}
	if repeated(folded) || sequential(folded) {
		return ErrCommon
	}
	// A password made of the account's own address or the service's name, with
	// at most some repeated filler around it, is the first thing guessed.
	for _, c := range context {
		c = strings.ToLower(strings.TrimSpace(c))
		words := []string{fold(c)}
		if local, _, ok := strings.Cut(c, "@"); ok {
			words = append(words, fold(local))
		}
		for _, w := range words {
			if len(w) >= 3 && repeated(strings.ReplaceAll(folded, w, "")) {
				return ErrCommon
			}
		}
	}
	return nil
}

// fold lowercases a password and drops everything but letters and digits, so
// "Correct Horse Battery Staple!" is checked as the phrase it is.
func fold(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// repeated reports whether s is one short unit over and over
// ("aaaaaaaaaaaaaaa", "passwordpassword", "abcabcabcabcabc"). An empty s is
// treated as repeated, so a password that is only a context value is refused.
func repeated(s string) bool {
	r := []rune(s)
	if len(r) == 0 {
		return true
	}
	for p := 1; p <= 8 && p < len(r); p++ {
		ok := true
		for i := p; i < len(r); i++ {
			if r[i] != r[i-p] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// walks are the sequences a person runs a finger along: the alphabet, the
// digits, and the rows and columns of a QWERTY keyboard.
var walks = []string{
	"abcdefghijklmnopqrstuvwxyz",
	"0123456789",
	"qwertyuiopasdfghjklzxcvbnm",
	"1234567890qwertyuiopasdfghjklzxcvbnm",
	"1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p",
	"qazwsxedcrfvtgbyhnujmikolp",
	"zaq1xsw2cde3vfr4bgt5nhy6mju7",
}

// sequential reports whether s is a run along one of the walks, forwards or
// backwards, wrapping around as often as needed.
func sequential(s string) bool {
	for _, w := range walks {
		loop := strings.Repeat(w, len(s)/len(w)+2)
		if strings.Contains(loop, s) || strings.Contains(loop, reverse(s)) {
			return true
		}
	}
	return false
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// Hash returns pw's Argon2id hash in the PHC string format
// ($argon2id$v=19$m=…,t=…,p=…$salt$hash), with a fresh random salt.
func Hash(pw string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(Normalize(pw)), salt, passes, memoryKiB, lanes, keyLen)
	enc := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, passes, lanes, enc(salt), enc(key)), nil
}

type params struct {
	memory  uint32
	passes  uint32
	lanes   uint8
	salt    []byte
	key     []byte
	version int
}

func parse(encoded string) (*params, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, errors.New("password: not an argon2id hash")
	}
	var p params
	if _, err := fmt.Sscanf(parts[2], "v=%d", &p.version); err != nil || p.version != argon2.Version {
		return nil, errors.New("password: unsupported argon2 version")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.passes, &p.lanes); err != nil {
		return nil, errors.New("password: malformed parameters")
	}
	// A hash read from the database is trusted, but a corrupt one must not be
	// able to ask for gigabytes.
	if p.memory == 0 || p.memory > 1<<20 || p.passes == 0 || p.passes > 16 || p.lanes == 0 {
		return nil, errors.New("password: parameters out of range")
	}
	var err error
	if p.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return nil, errors.New("password: malformed salt")
	}
	if p.key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(p.key) == 0 {
		return nil, errors.New("password: malformed hash")
	}
	return &p, nil
}

// Verify reports whether pw matches encoded, comparing in constant time. A
// malformed hash is an error, never a match.
func Verify(pw, encoded string) (bool, error) {
	p, err := parse(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(Normalize(pw)), p.salt, p.passes, p.memory, p.lanes, uint32(len(p.key)))
	return subtle.ConstantTimeCompare(got, p.key) == 1, nil
}

// NeedsRehash reports whether encoded was made with other parameters than new
// hashes get, so a sign-in that just proved the password can store a new hash.
func NeedsRehash(encoded string) bool {
	p, err := parse(encoded)
	return err != nil || p.memory != memoryKiB || p.passes != passes || p.lanes != lanes || len(p.key) != keyLen
}

var (
	decoyOnce sync.Once
	decoy     string
)

// Decoy does the work of one verification against a hash nobody can match.
//
// A sign-in for an address with no account, or an account with no password,
// calls it so that it takes as long as one with a wrong password: otherwise
// the time a refusal takes says whether the address has a password.
func Decoy(pw string) {
	decoyOnce.Do(func() {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		decoy, _ = Hash(base64.RawStdEncoding.EncodeToString(b))
	})
	_, _ = Verify(pw, decoy)
}

//go:embed common.txt
var commonList string

// common is the embedded list of passwords guessed first, folded the way
// Check folds a candidate. Only entries long enough to pass MinLength matter,
// so the list is mostly the long ones from public breach corpora; the repeated
// and sequential checks catch the patterns a list cannot enumerate.
var common = func() map[string]bool {
	m := map[string]bool{}
	for _, line := range strings.Split(commonList, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m[strings.ToLower(line)] = true
		if f := fold(line); f != "" {
			m[f] = true
		}
	}
	return m
}()
