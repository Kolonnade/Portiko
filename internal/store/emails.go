package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Errors of the email-management methods.
var (
	// ErrEmailLimit: the account already holds as many addresses as it may.
	ErrEmailLimit = errors.New("store: the account holds the most addresses it may")
	// ErrEmailTaken: the address is already on an account, this one or another.
	// Callers must not tell the two apart, or tell this from a wrong code.
	ErrEmailTaken = errors.New("store: the address is already on an account")
	// ErrPrimaryEmail: the primary address cannot be removed.
	ErrPrimaryEmail = errors.New("store: cannot remove the primary address")
)

// Email is one address on an account.
type Email struct {
	ID         int64
	Address    string
	Primary    bool
	VerifiedAt time.Time
}

// Emails lists the account's verified addresses, the primary first and then in
// the order they were added.
func (d *DB) Emails(ctx context.Context, userID int64) ([]Email, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT id, value, is_primary, verified_at FROM identifiers
		  WHERE user_id = $1 AND kind = 'email' AND verified_at IS NOT NULL
		  ORDER BY is_primary DESC, id ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Email
	for rows.Next() {
		var e Email
		if err := rows.Scan(&e.ID, &e.Address, &e.Primary, &e.VerifiedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// EmailInUse reports whether a verified address is on any account.
func (d *DB) EmailInUse(ctx context.Context, email string) (bool, error) {
	var in bool
	err := d.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM identifiers WHERE kind = 'email' AND value = $1)`,
		NormalizeEmail(email)).Scan(&in)
	return in, err
}

// CreatePendingEmail records an address being added to an account, with the
// code sent to it.
func (d *DB) CreatePendingEmail(ctx context.Context, userID int64, email, code string, expires time.Time) error {
	_, err := d.pool.Exec(ctx,
		`INSERT INTO pending_emails (user_id, email, code, expires_at) VALUES ($1, $2, $3, $4)`,
		userID, NormalizeEmail(email), code, expires)
	return err
}

// AddVerifiedEmail checks the code sent to an address being added and, when it
// is right, puts the address on the account as a backup.
//
// The guessing is bounded as VerifyPendingCode bounds it, and by the same
// per-address budget: the code is the same six digits, and the address is the
// same address whichever flow asked for it.
//
// The limit and the uniqueness are checked in the transaction that inserts, with
// the account's addresses locked, so two additions at once cannot both squeeze
// under the limit and an address registered elsewhere in the meantime is
// refused.
func (d *DB) AddVerifiedEmail(ctx context.Context, userID int64, email, code string, limit int) (*Email, error) {
	email = NormalizeEmail(email)
	guess, err := d.Allow(ctx, RateBucketCodeGuess, HashToken(email),
		MaxCodeAttemptsPerAddress, CodeAttemptWindow)
	if err != nil {
		return nil, err
	}
	if !guess.OK {
		return nil, ErrTooManyAttempts
	}

	var (
		stored   string
		attempts int
		expires  time.Time
	)
	// Counted in its own statement, committed whatever the answer, so a wrong
	// guess is spent even when the transaction below never runs.
	err = d.pool.QueryRow(ctx,
		`UPDATE pending_emails SET attempts = attempts + 1
		  WHERE id = (SELECT id FROM pending_emails
		               WHERE user_id = $1 AND email = $2 ORDER BY id DESC LIMIT 1)
		 RETURNING code, attempts, expires_at`, userID, email).Scan(&stored, &attempts, &expires)
	if err != nil {
		return nil, norm(err)
	}
	switch {
	case attempts > MaxCodeAttempts:
		return nil, ErrTooManyAttempts
	case time.Now().After(expires):
		return nil, ErrExpired
	case !subtleEqual(stored, code):
		return nil, ErrBadCode
	}

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// FOR UPDATE cannot be combined with an aggregate, so lock and count apart.
	rows, err := tx.Query(ctx,
		`SELECT id FROM identifiers WHERE user_id = $1 AND kind = 'email' FOR UPDATE`, userID)
	if err != nil {
		return nil, err
	}
	held := 0
	for rows.Next() {
		held++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if held >= limit {
		return nil, ErrEmailLimit
	}

	var e Email
	err = tx.QueryRow(ctx,
		`INSERT INTO identifiers (user_id, kind, value, verified_at, is_primary)
		 VALUES ($1, 'email', $2, now(), FALSE)
		 RETURNING id, value, is_primary, verified_at`, userID, email).
		Scan(&e.ID, &e.Address, &e.Primary, &e.VerifiedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return nil, ErrEmailTaken
	}
	if err != nil {
		return nil, fmt.Errorf("store: adding an address: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM pending_emails WHERE user_id = $1 AND email = $2`, userID, email); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &e, nil
}

// SetPrimaryEmail makes one of the account's addresses its primary and returns
// the address that was primary before. An id that is not one of this account's
// verified addresses is ErrNotFound.
func (d *DB) SetPrimaryEmail(ctx context.Context, userID, id int64) (previous, current string, err error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx,
		`SELECT id, value, is_primary FROM identifiers
		  WHERE user_id = $1 AND kind = 'email' AND verified_at IS NOT NULL
		  ORDER BY id FOR UPDATE`, userID)
	if err != nil {
		return "", "", err
	}
	found := false
	for rows.Next() {
		var (
			rid     int64
			value   string
			primary bool
		)
		if err := rows.Scan(&rid, &value, &primary); err != nil {
			rows.Close()
			return "", "", err
		}
		if primary {
			previous = value
		}
		if rid == id {
			current, found = value, true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", "", err
	}
	if !found {
		return "", "", ErrNotFound
	}
	if previous == current {
		return previous, current, nil
	}
	// Two statements, old then new: the one-primary index is checked row by row.
	if _, err := tx.Exec(ctx,
		`UPDATE identifiers SET is_primary = FALSE WHERE user_id = $1 AND kind = 'email' AND is_primary`, userID); err != nil {
		return "", "", err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE identifiers SET is_primary = TRUE WHERE id = $1 AND user_id = $2`, id, userID); err != nil {
		return "", "", err
	}
	return previous, current, tx.Commit(ctx)
}

// RemoveEmail takes a backup address off the account and returns it. The
// primary is refused with ErrPrimaryEmail; an id that is not this account's is
// ErrNotFound.
func (d *DB) RemoveEmail(ctx context.Context, userID, id int64) (string, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		value   string
		primary bool
	)
	err = tx.QueryRow(ctx,
		`SELECT value, is_primary FROM identifiers
		  WHERE id = $1 AND user_id = $2 AND kind = 'email' FOR UPDATE`, id, userID).Scan(&value, &primary)
	if err != nil {
		return "", norm(err)
	}
	if primary {
		return "", ErrPrimaryEmail
	}
	if _, err := tx.Exec(ctx, `DELETE FROM identifiers WHERE id = $1`, id); err != nil {
		return "", err
	}
	return value, tx.Commit(ctx)
}
