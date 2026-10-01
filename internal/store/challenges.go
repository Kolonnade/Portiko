package store

import (
	"context"
	"fmt"
	"time"
)

// Create stores an in-flight ceremony.
func (d *DB) Create(ctx context.Context, c Challenge) error {
	_, err := d.pool.Exec(ctx,
		`INSERT INTO webauthn_challenges
		   (challenge, purpose, user_id, pending_registration_token, session_data, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		c.Challenge, c.Purpose, c.UserID, c.PendingTok, c.SessionData, c.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store: creating challenge: %w", err)
	}
	return nil
}

// ConsumeChallenge atomically deletes and returns a challenge.
//
// DELETE ... RETURNING in a single statement, deliberately: a read followed by a
// delete leaves a window in which the same challenge is used twice, which is
// precisely the replay a challenge exists to prevent. The expiry is checked here
// too, so an expired row is consumed and rejected rather than left to linger.
func (d *DB) ConsumeChallenge(ctx context.Context, challenge []byte, purpose string) (*Challenge, error) {
	var c Challenge
	err := d.pool.QueryRow(ctx,
		`DELETE FROM webauthn_challenges
		  WHERE challenge = $1 AND purpose = $2
		 RETURNING challenge, purpose, user_id, pending_registration_token, session_data, expires_at`,
		challenge, purpose).
		Scan(&c.Challenge, &c.Purpose, &c.UserID, &c.PendingTok, &c.SessionData, &c.ExpiresAt)
	if err != nil {
		return nil, norm(err)
	}
	if time.Now().After(c.ExpiresAt) {
		return nil, ErrExpired
	}
	return &c, nil
}

// SweepExpired removes challenges and pending registrations that have lapsed.
func (d *DB) SweepExpired(ctx context.Context) (int64, error) {
	tag, err := d.pool.Exec(ctx, `DELETE FROM webauthn_challenges WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	n := tag.RowsAffected()
	tag2, err := d.pool.Exec(ctx, `DELETE FROM pending_registrations WHERE expires_at < now()`)
	if err != nil {
		return n, err
	}
	n += tag2.RowsAffected()
	tag3, err := d.pool.Exec(ctx, `DELETE FROM auth_requests WHERE expires_at < now()`)
	if err != nil {
		return n, err
	}
	n += tag3.RowsAffected()
	counters, err := d.sweepRateCounters(ctx)
	if err != nil {
		return n, err
	}
	return n + counters, nil
}

// PendingRegistration is an email awaiting its one-time code.
type PendingRegistration struct {
	Email     string
	Token     string
	Code      string
	Attempts  int
	Purpose   string
	ExpiresAt time.Time
}

// CreatePending records an email mid-registration or mid-recovery.
func (d *DB) CreatePending(ctx context.Context, p PendingRegistration) error {
	_, err := d.pool.Exec(ctx,
		`INSERT INTO pending_registrations (email, token, code, purpose, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		NormalizeEmail(p.Email), p.Token, p.Code, p.Purpose, p.ExpiresAt)
	return err
}

// VerifyPendingCode checks a one-time code and consumes the row on success.
//
// Two counters bound the guessing, and both are needed:
//
//   - The per-row counter, incremented inside the same statement that reads the
//     row, so guesses against one code cannot be parallelised.
//   - The per-ADDRESS counter, which is the one the per-row counter alone got
//     wrong. Asking for another code created another row with five fresh guesses,
//     so five-per-code plus unlimited codes was the whole six-digit space in about
//     200,000 requests. This counter is not reset by a new code, by consuming one,
//     or by a row expiring, because it does not live in the rows. (#0012)
//
// The address counter is taken before the row is read, so a guess at an address
// with no pending code — which is what enumeration looks like — costs the same as
// any other.
func (d *DB) VerifyPendingCode(ctx context.Context, email, code string) (*PendingRegistration, error) {
	email = NormalizeEmail(email)

	// Hashed: this counter must not become a list of the addresses that have been
	// guessed at, and it only ever needs equality.
	guess, err := d.Allow(ctx, RateBucketCodeGuess, HashToken(email),
		MaxCodeAttemptsPerAddress, CodeAttemptWindow)
	if err != nil {
		return nil, err
	}
	if !guess.OK {
		return nil, ErrTooManyAttempts
	}

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var p PendingRegistration
	err = tx.QueryRow(ctx,
		`UPDATE pending_registrations
		    SET attempts = attempts + 1
		  WHERE id = (SELECT id FROM pending_registrations
		               WHERE email = $1 ORDER BY id DESC LIMIT 1)
		 RETURNING email, token, COALESCE(code, ''), attempts, purpose, expires_at`,
		email).Scan(&p.Email, &p.Token, &p.Code, &p.Attempts, &p.Purpose, &p.ExpiresAt)
	if err != nil {
		return nil, norm(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	switch {
	case p.Attempts > MaxCodeAttempts:
		return nil, ErrTooManyAttempts
	case time.Now().After(p.ExpiresAt):
		return nil, ErrExpired
	case subtleEqual(p.Code, code):
		return &p, nil
	default:
		return nil, ErrBadCode
	}
}

// PendingByToken loads a pending registration by its token.
func (d *DB) PendingByToken(ctx context.Context, token string) (*PendingRegistration, error) {
	var p PendingRegistration
	err := d.pool.QueryRow(ctx,
		`SELECT email, token, COALESCE(code, ''), attempts, purpose, expires_at
		   FROM pending_registrations WHERE token = $1`, token).
		Scan(&p.Email, &p.Token, &p.Code, &p.Attempts, &p.Purpose, &p.ExpiresAt)
	if err != nil {
		return nil, norm(err)
	}
	if time.Now().After(p.ExpiresAt) {
		return nil, ErrExpired
	}
	return &p, nil
}

// DeletePending removes a consumed pending registration.
func (d *DB) DeletePending(ctx context.Context, token string) error {
	_, err := d.pool.Exec(ctx, `DELETE FROM pending_registrations WHERE token = $1`, token)
	return err
}
