package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Per-account backoff on failed password sign-ins (migration 000012).
//
// The endpoint limits bound what one address and one IP can try; this bounds
// what everybody together can try against one account. The first few failures
// are free, because people mistype. After that each attempt must wait, the wait
// doubling per failure up to a ceiling, so guessing settles at about one try an
// hour per account however many addresses it comes from. A success resets it.
const (
	// FreePasswordAttempts is how many consecutive failures cost nothing.
	FreePasswordAttempts = 5
	// PasswordBackoffBase is the wait after the first failure past the free ones.
	PasswordBackoffBase = 30 * time.Second
	// PasswordBackoffMax is the longest wait.
	PasswordBackoffMax = time.Hour
)

// ErrPasswordLocked is returned when an account's password is waiting out its
// backoff. It is never told apart to a caller: a refusal looks like a wrong
// password, so the backoff cannot reveal that an address has one.
var ErrPasswordLocked = errors.New("store: password attempts are backing off")

// Password is an account's password row. Hash is never shown to anybody.
type Password struct {
	UserID          int64
	Hash            string
	RestrictedUntil *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastUsedAt      *time.Time
}

const passwordColumns = `user_id, hash, restricted_until, created_at, updated_at, last_used_at`

func scanPassword(row pgx.Row) (*Password, error) {
	var p Password
	if err := row.Scan(&p.UserID, &p.Hash, &p.RestrictedUntil, &p.CreatedAt, &p.UpdatedAt, &p.LastUsedAt); err != nil {
		return nil, norm(err)
	}
	return &p, nil
}

// PasswordOf returns the account's password row, or ErrNotFound when it has
// none.
func (d *DB) PasswordOf(ctx context.Context, userID int64) (*Password, error) {
	return scanPassword(d.pool.QueryRow(ctx,
		`SELECT `+passwordColumns+` FROM passwords WHERE user_id = $1`, userID))
}

// SetPassword gives the account a password, replacing the one it had, and
// reports whether it replaced one. restrictedUntil is the recovery hold the new
// password carries (nil for none). The backoff starts again.
func (d *DB) SetPassword(ctx context.Context, userID int64, hash string, restrictedUntil *time.Time) (replaced bool, err error) {
	return setPasswordTx(ctx, d.pool, userID, hash, restrictedUntil)
}

type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func setPasswordTx(ctx context.Context, q queryRower, userID int64, hash string, restrictedUntil *time.Time) (bool, error) {
	// xmax = 0 only on a freshly inserted row; an updated one carries the
	// transaction that updated it.
	var inserted bool
	err := q.QueryRow(ctx,
		`INSERT INTO passwords (user_id, hash, restricted_until)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_id) DO UPDATE
		   SET hash = EXCLUDED.hash, restricted_until = EXCLUDED.restricted_until,
		       failed_attempts = 0, locked_until = NULL, updated_at = now()
		 RETURNING (xmax = 0)`, userID, hash, restrictedUntil).Scan(&inserted)
	if err != nil {
		return false, fmt.Errorf("store: setting password: %w", err)
	}
	return !inserted, nil
}

// RemovePassword deletes the account's password, refusing when the account
// has no passkey to sign in with instead (ErrLastCredential). An account with
// no password is ErrNotFound.
//
// The account's passkey rows are locked before they are counted, in the same
// order Revoke locks them, so a password removal and a passkey revoke at once
// cannot both pass the check and leave the account with nothing.
func (d *DB) RemovePassword(ctx context.Context, userID int64) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	passkeys, err := lockPasskeys(ctx, tx, userID)
	if err != nil {
		return err
	}
	var one int
	if err := tx.QueryRow(ctx, `SELECT 1 FROM passwords WHERE user_id = $1 FOR UPDATE`, userID).Scan(&one); err != nil {
		return norm(err)
	}
	if passkeys == 0 {
		return ErrLastCredential
	}
	if _, err := tx.Exec(ctx, `DELETE FROM passwords WHERE user_id = $1`, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// lockPasskeys locks the account's passkey rows and counts them. FOR UPDATE
// cannot be combined with an aggregate, so the rows are read and counted here.
func lockPasskeys(ctx context.Context, tx pgx.Tx, userID int64) (int, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM passkey_credentials WHERE user_id = $1 ORDER BY id FOR UPDATE`, userID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	return n, rows.Err()
}

// BeginPasswordAttempt charges one attempt against the account's backoff and
// returns the password to check it against.
//
// It counts first and lets the caller check afterwards, as Allow does: an
// attempt costs a slot whether or not it succeeds, and the UPDATE takes the
// row lock, so parallel guesses queue behind each other instead of all
// reading the same "not locked yet". Past FreePasswordAttempts the attempt
// also sets the wait the next one must sit out. PasswordSucceeded clears both.
//
// ErrNotFound: the account has no password. ErrPasswordLocked: it is waiting.
func (d *DB) BeginPasswordAttempt(ctx context.Context, userID int64) (*Password, error) {
	p, err := scanPassword(d.pool.QueryRow(ctx,
		`UPDATE passwords
		    SET failed_attempts = failed_attempts + 1,
		        locked_until = CASE WHEN failed_attempts + 1 > $2
		            THEN now() + make_interval(secs => least($3 * power(2, failed_attempts - $2), $4))
		            ELSE NULL END
		  WHERE user_id = $1 AND (locked_until IS NULL OR locked_until <= now())
		 RETURNING `+passwordColumns,
		userID, FreePasswordAttempts, PasswordBackoffBase.Seconds(), PasswordBackoffMax.Seconds()))
	if errors.Is(err, ErrNotFound) {
		var one int
		if err := d.pool.QueryRow(ctx, `SELECT 1 FROM passwords WHERE user_id = $1`, userID).Scan(&one); err == nil {
			return nil, ErrPasswordLocked
		}
		return nil, ErrNotFound
	}
	return p, err
}

// PasswordSucceeded records a sign-in with the password: the backoff resets
// and last_used_at moves. A non-empty rehash replaces the stored hash, for a
// hash made with older parameters.
func (d *DB) PasswordSucceeded(ctx context.Context, userID int64, rehash string) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE passwords
		    SET failed_attempts = 0, locked_until = NULL, last_used_at = now(),
		        hash = COALESCE(NULLIF($2, ''), hash)
		  WHERE user_id = $1`, userID, rehash)
	return err
}

// takePending deletes a pending registration and returns it, so the code it
// was verified with finishes exactly one ceremony.
func takePending(ctx context.Context, tx pgx.Tx, token string) (*PendingRegistration, error) {
	var p PendingRegistration
	err := tx.QueryRow(ctx,
		`DELETE FROM pending_registrations WHERE token = $1
		 RETURNING email, token, COALESCE(code, ''), attempts, purpose, expires_at`, token).
		Scan(&p.Email, &p.Token, &p.Code, &p.Attempts, &p.Purpose, &p.ExpiresAt)
	if err != nil {
		return nil, norm(err)
	}
	if time.Now().After(p.ExpiresAt) {
		return nil, ErrExpired
	}
	return &p, nil
}

// PasswordEnrollment is what FinishPasswordEnrollment did.
type PasswordEnrollment struct {
	User *User
	// Recovered is true when the account already existed.
	Recovered bool
	// Replaced is true when the account already had a password.
	Replaced bool
}

// FinishPasswordEnrollment ends a verified registration or recovery with a
// password instead of a passkey, in one transaction: the pending row is taken
// (so its token finishes one ceremony only), and either a new account is
// created with its address and password, or the existing account's password
// is set.
//
// purpose must match the pending row's, so a caller that decided what to allow
// from one purpose cannot be handed the other. recoveryHold is the
// restricted_until a recovered password gets.
func (d *DB) FinishPasswordEnrollment(ctx context.Context, token, purpose, hash string, recoveryHold *time.Time) (*PasswordEnrollment, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	p, err := takePending(ctx, tx, token)
	if err != nil {
		return nil, err
	}
	if p.Purpose != purpose {
		return nil, ErrNotFound
	}
	out := &PasswordEnrollment{}
	switch p.Purpose {
	case "recovery":
		u, err := scanUser(tx.QueryRow(ctx,
			`SELECT `+userColumns+`
			   FROM users u JOIN identifiers i ON i.user_id = u.id
			  WHERE i.kind = 'email' AND i.value = $1 AND i.verified_at IS NOT NULL`, p.Email))
		if err != nil {
			return nil, err
		}
		replaced, err := setPasswordTx(ctx, tx, u.ID, hash, recoveryHold)
		if err != nil {
			return nil, err
		}
		out.User, out.Recovered, out.Replaced = u, true, replaced
	default:
		subject, err := NewSubject()
		if err != nil {
			return nil, err
		}
		var u User
		if err := tx.QueryRow(ctx,
			`INSERT INTO users (subject, active) VALUES ($1, TRUE)
			 RETURNING id, subject, COALESCE(display_name, ''), COALESCE(avatar, ''), profile_updated_at, active, created_at`,
			subject).Scan(&u.ID, &u.Subject, &u.DisplayName, &u.Avatar, &u.ProfileUpdatedAt, &u.Active, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: inserting user: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO identifiers (user_id, kind, value, verified_at, is_primary)
			 VALUES ($1, 'email', $2, now(), TRUE)`, u.ID, p.Email); err != nil {
			return nil, fmt.Errorf("store: inserting identifier: %w", err)
		}
		if _, err := setPasswordTx(ctx, tx, u.ID, hash, nil); err != nil {
			return nil, err
		}
		out.User = &u
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return out, nil
}
