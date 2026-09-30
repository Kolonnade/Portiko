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

// MaxCodeAttempts bounds guesses against a single one-time code.
const MaxCodeAttempts = 5

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
