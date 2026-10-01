// Package store is Portiko's persistence: accounts, passkeys, ceremonies,
// browser sessions, clients, authorization requests and refresh tokens, all in
// PostgreSQL so a deployment can run more than one replica and survive a restart
// mid-sign-in.
package store

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// User is an account.
type User struct {
	ID          int64
	Subject     string // opaque "usr_…", the value that leaves this service
	DisplayName string // chosen on the profile page; empty until then
	Avatar      string // a profile avatar key; empty until chosen
	// ProfileUpdatedAt is the profile's version: when it last changed, in Unix
	// seconds. It leaves the service as the updated_at claim.
	ProfileUpdatedAt int64
	Active           bool
	CreatedAt        time.Time
}

// Challenge is an in-flight WebAuthn ceremony.
type Challenge struct {
	Challenge   []byte
	Purpose     string
	UserID      *int64
	PendingTok  *string
	SessionData []byte
	ExpiresAt   time.Time
}

// ErrLastCredential is returned when revoking would leave an account with no
// way to sign in.
var ErrLastCredential = errors.New("store: cannot revoke the last credential")

// Guess limits on one-time codes.
//
// Two numbers rather than one, because the dangerous case is not many guesses at
// one code — it is a few guesses at each of many codes, which a per-code limit
// does not see at all.
const (
	// MaxCodeAttempts bounds guesses against a single one-time code.
	MaxCodeAttempts = 5
	// MaxCodeAttemptsPerAddress bounds guesses against one address across every
	// code it has been sent, inside CodeAttemptWindow. It survives a new code
	// being requested, which is what #0012 was: a new code meant a new row and a
	// fresh set of five.
	MaxCodeAttemptsPerAddress = 10
	// CodeAttemptWindow is how long the per-address budget takes to refill. Long
	// enough that covering the code space is hopeless, short enough that somebody
	// who genuinely fumbled their code is not locked out for the day.
	CodeAttemptWindow = time.Hour
)

// Errors surfaced by the one-time-code and challenge paths.
//
// These are internal detail: every one of them is reported to a client as the
// same generic failure, so that the response cannot be used to probe whether an
// account exists or how far a guess got.
var (
	ErrExpired         = errors.New("store: expired")
	ErrBadCode         = errors.New("store: incorrect code")
	ErrTooManyAttempts = errors.New("store: too many attempts")
)

// subtleEqual compares two secrets in constant time.
func subtleEqual(a, b string) bool {
	return len(a) > 0 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// HashToken hashes a secret for storage.
//
// Codes, refresh tokens, client secrets and browser identifiers are stored
// hashed, so a leaked database dump is not a set of working credentials. These
// are high-entropy random values, so a fast hash is appropriate — this is not a
// password.
func HashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// SecretMatches reports whether a presented secret hashes to a stored hash, in
// constant time.
func SecretMatches(presented, storedHash string) bool {
	return subtleEqual(HashToken(presented), storedHash)
}
