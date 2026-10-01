// Package accounts implements the three WebAuthn ceremonies — registration,
// login and recovery — over Postgres.
//
// Ported from ShortLinks, which shipped these flows and recorded the mistakes
// worth not repeating. The comments name the traps at the point where the code
// avoids them.
package accounts

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Kolonnade/Portiko/internal/config"
	"github.com/Kolonnade/Portiko/internal/mailer"
	"github.com/Kolonnade/Portiko/internal/store"
)

// Ceremony lifetimes. Registration is short because the user is actively in the
// flow; recovery is longer because it starts from an email that may be read on
// another device.
const (
	CodeTTL          = 10 * time.Minute
	RecoveryCodeTTL  = 15 * time.Minute
	ChallengeTTL     = 5 * time.Minute
	codeDigits       = 6
	pendingTokenSize = 32
)

// ErrAuthFailed is the single error every failed ceremony returns.
//
// One error for every cause, deliberately: a caller must not be able to tell
// "no such account" from "wrong code" from "expired challenge", because that
// difference is an account-enumeration oracle. The server logs name the real
// step (see logStep); the client never learns it.
var ErrAuthFailed = errors.New("authentication failed")

// Service runs the ceremonies.
type Service struct {
	cfg    *config.Config
	db     *store.DB
	wa     *webauthn.WebAuthn
	mailer mailer.Mailer
}

// Caller describes the request a ceremony arrived on.
//
// It is passed in rather than read from the context because these two values are
// what makes an audit row and a security notice answerable — "was this me, from
// there?" — and a value that must be present is better as a parameter the
// compiler insists on than as something a handler can forget to attach.
type Caller struct {
	IP        string
	UserAgent string
}

// New builds the service.
func New(cfg *config.Config, db *store.DB, wa *webauthn.WebAuthn, m mailer.Mailer) *Service {
	return &Service{cfg: cfg, db: db, wa: wa, mailer: m}
}

// logStep records which step actually failed.
//
// Because the client-facing error is deliberately useless, the server must say
// exactly where a ceremony died. ShortLinks lost two rounds of investigation to
// a passkey bug largely because this line did not exist yet, and the first two
// hypotheses were both wrong.
func logStep(ctx context.Context, step string, err error) {
	slog.WarnContext(ctx, "ceremony failed", "step", step, "err", err)
}

// newCode returns a zero-padded numeric one-time code.
func newCode() (string, error) {
	max := big.NewInt(1)
	for i := 0; i < codeDigits; i++ {
		max.Mul(max, big.NewInt(10))
	}
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", codeDigits, n.Int64()), nil
}

func newToken() (string, error) {
	b := make([]byte, pendingTokenSize)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AMR reports how a passkey ceremony authenticated, in RFC 8176 terms. A
// passkey that can be backed up is a synced, software-held key ("swk"); one that
// cannot is bound to its hardware ("hwk"). User verification is always required
// here, so "user" is always present.
func AMR(backupEligible bool) []string {
	if backupEligible {
		return []string{"swk", "user"}
	}
	return []string{"hwk", "user"}
}
