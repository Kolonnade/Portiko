package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Kolonnade/Portiko/internal/passkey"
)

// NormalizeEmail lowercases and trims an address.
//
// Storing the normalized form is what makes the UNIQUE constraint meaningful:
// without it "A@b.com" and "a@b.com" are two accounts, and the second one
// silently shadows the first at sign-in.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

const userColumns = `u.id, u.subject, COALESCE(u.display_name, ''), COALESCE(u.avatar, ''), u.profile_updated_at, u.active, u.created_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Subject, &u.DisplayName, &u.Avatar, &u.ProfileUpdatedAt, &u.Active, &u.CreatedAt); err != nil {
		return nil, norm(err)
	}
	return &u, nil
}

// ByID looks up an account by primary key.
func (d *DB) ByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(d.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users u WHERE u.id = $1`, id))
}

// BySubject looks up an account by its opaque subject.
func (d *DB) BySubject(ctx context.Context, subject string) (*User, error) {
	return scanUser(d.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users u WHERE u.subject = $1`, subject))
}

// ByIdentifier looks up an account by a verified email or phone.
//
// Unverified identifiers are excluded: claiming an address you cannot read must
// never be enough to reach an account.
func (d *DB) ByIdentifier(ctx context.Context, kind, value string) (*User, error) {
	return scanUser(d.pool.QueryRow(ctx,
		`SELECT `+userColumns+`
		   FROM users u
		   JOIN identifiers i ON i.user_id = u.id
		  WHERE i.kind = $1 AND i.value = $2 AND i.verified_at IS NOT NULL`,
		kind, NormalizeEmail(value)))
}

// PrimaryEmail returns the account's primary verified email.
func (d *DB) PrimaryEmail(ctx context.Context, userID int64) (string, error) {
	var email string
	err := d.pool.QueryRow(ctx,
		`SELECT value FROM identifiers
		  WHERE user_id = $1 AND kind = 'email' AND verified_at IS NOT NULL
		  ORDER BY is_primary DESC, id ASC LIMIT 1`, userID).Scan(&email)
	return email, norm(err)
}

// FinishRegistration creates the account, its verified email and its first
// passkey in one transaction.
//
// It is one method, not four, because a partial failure must leave nothing
// behind. A user row with no credential is an account nobody can ever sign in
// to — and because enrollment is the only way to get a credential, it would
// also permanently block that email from registering again.
func (d *DB) FinishRegistration(ctx context.Context, email string, cred passkey.StoredCredential, handle []byte) (*User, error) {
	email = NormalizeEmail(email)

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	subject, err := NewSubject()
	if err != nil {
		return nil, err
	}

	// The display name starts empty. It used to be a copy of the email, which put
	// the address into the passkey's user name and onto every page.
	var u User
	err = tx.QueryRow(ctx,
		`INSERT INTO users (subject, active)
		 VALUES ($1, TRUE)
		 RETURNING id, subject, COALESCE(display_name, ''), COALESCE(avatar, ''), profile_updated_at, active, created_at`,
		subject).
		Scan(&u.ID, &u.Subject, &u.DisplayName, &u.Avatar, &u.ProfileUpdatedAt, &u.Active, &u.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: inserting user: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO identifiers (user_id, kind, value, verified_at, is_primary)
		 VALUES ($1, 'email', $2, now(), TRUE)`, u.ID, email); err != nil {
		return nil, fmt.Errorf("store: inserting identifier: %w", err)
	}

	cred.UserID = u.ID
	cred.UserHandle = handle
	if err := insertCredentialTx(ctx, tx, cred); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return &u, nil
}

// UpdateProfile sets the display name and avatar and returns the profile's new
// version (updated_at, Unix seconds). Callers validate both with package
// profile first; the store only persists.
//
// The version is forced to rise by at least one on every save, so two saves
// within the same second still read as two changes to a site comparing them.
func (d *DB) UpdateProfile(ctx context.Context, userID int64, displayName, avatar string) (int64, error) {
	var version int64
	err := d.pool.QueryRow(ctx,
		`UPDATE users
		    SET display_name = $2, avatar = $3,
		        profile_updated_at = GREATEST(extract(epoch FROM now())::bigint, profile_updated_at + 1)
		  WHERE id = $1
		 RETURNING profile_updated_at`,
		userID, displayName, avatar).Scan(&version)
	return version, norm(err)
}

// UserHandles returns the distinct WebAuthn user handles on the account's
// passkeys — what the browser needs to tell the passkey provider that the
// account's name changed.
func (d *DB) UserHandles(ctx context.Context, userID int64) ([][]byte, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT DISTINCT user_handle FROM passkey_credentials
		  WHERE user_id = $1 AND user_handle IS NOT NULL`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out [][]byte
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// TouchLogin records a successful sign-in.
func (d *DB) TouchLogin(ctx context.Context, userID int64) error {
	_, err := d.pool.Exec(ctx, `UPDATE users SET last_login_at = $1 WHERE id = $2`,
		time.Now(), userID)
	return err
}
