package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Kolonnade/Portiko/internal/passkey"
)

const credColumns = `id, user_id, credential_id, public_key, user_handle,
	COALESCE(aaguid::text, ''), sign_count, COALESCE(device_name, ''),
	backup_eligible, backup_state, rp_id`

func scanCredential(row pgx.Row) (*passkey.StoredCredential, error) {
	var c passkey.StoredCredential
	var aaguid string
	if err := row.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.UserHandle,
		&aaguid, &c.SignCount, &c.DeviceName, &c.BackupEligible, &c.BackupState, &c.RPID); err != nil {
		return nil, norm(err)
	}
	c.AAGUID = passkey.ParseAAGUID(aaguid)
	return &c, nil
}

// ByCredentialID resolves the credential an assertion was produced with.
//
// The lookup is on the raw bytes. Encoding on the way in and decoding on the way
// out is an extra place for a base64 variant mismatch to hide, and that class of
// bug fails silently.
func (d *DB) ByCredentialID(ctx context.Context, credentialID []byte) (*passkey.StoredCredential, error) {
	return scanCredential(d.pool.QueryRow(ctx,
		`SELECT `+credColumns+` FROM passkey_credentials WHERE credential_id = $1`, credentialID))
}

// ByUser lists an account's credentials.
func (d *DB) ByUser(ctx context.Context, userID int64) ([]passkey.StoredCredential, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT `+credColumns+` FROM passkey_credentials WHERE user_id = $1 ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []passkey.StoredCredential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// Insert stores a newly enrolled credential.
func (d *DB) Insert(ctx context.Context, c passkey.StoredCredential) error {
	return insertCredentialTx(ctx, d.pool, c)
}

// queryExecer is satisfied by both the pool and a transaction, so the same
// insert serves the standalone case and the registration transaction.
type queryExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// insertCredentialTx works against either the pool or a transaction.
func insertCredentialTx(ctx context.Context, q queryExecer, c passkey.StoredCredential) error {
	var aaguid any
	if s := passkey.FormatAAGUID(c.AAGUID); s != "" {
		aaguid = s
	}
	_, err := q.Exec(ctx,
		`INSERT INTO passkey_credentials
		   (user_id, credential_id, public_key, user_handle, aaguid, sign_count,
		    device_name, backup_eligible, backup_state, rp_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		c.UserID, c.CredentialID, c.PublicKey, c.UserHandle, aaguid, c.SignCount,
		nullIfEmpty(c.DeviceName), c.BackupEligible, c.BackupState, c.RPID)
	if err != nil {
		return fmt.Errorf("store: inserting credential: %w", err)
	}
	return nil
}

// RecordLogin updates the mutable half of a credential after a successful
// assertion.
//
// backup_eligible is deliberately absent from this UPDATE. go-webauthn treats
// Backup Eligible as immutable and compares the stored value against every
// assertion; overwriting it is how a synced passkey stops working. Only
// backup_state, sign_count and last_used_at move.
func (d *DB) RecordLogin(ctx context.Context, credentialID []byte, signCount uint32, backupState bool) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE passkey_credentials
		    SET sign_count = $2, backup_state = $3, last_used_at = now()
		  WHERE credential_id = $1`,
		credentialID, int64(signCount), backupState)
	return err
}

// ManagedCredential is one passkey as the account holder sees it: display
// metadata only, never the public key or the raw credential id.
type ManagedCredential struct {
	ID         int64
	Name       string
	AAGUID     []byte
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// ListManaged lists an account's passkeys, oldest first, with when each was
// created and last used.
func (d *DB) ListManaged(ctx context.Context, userID int64) ([]ManagedCredential, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT id, COALESCE(device_name, ''), COALESCE(aaguid::text, ''), created_at, last_used_at
		   FROM passkey_credentials WHERE user_id = $1 ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ManagedCredential{}
	for rows.Next() {
		var c ManagedCredential
		var aaguid string
		if err := rows.Scan(&c.ID, &c.Name, &aaguid, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, err
		}
		c.AAGUID = passkey.ParseAAGUID(aaguid)
		out = append(out, c)
	}
	return out, rows.Err()
}

// RenameCredential names one of the account's passkeys. A credential that is
// not the account's own is ErrNotFound, exactly as one that does not exist, so
// the answer never reveals that another account's id is valid. It returns the
// previous name for the audit trail.
func (d *DB) RenameCredential(ctx context.Context, userID, credentialID int64, name string) (previous string, err error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(device_name, '') FROM passkey_credentials WHERE id = $1 AND user_id = $2 FOR UPDATE`,
		credentialID, userID).Scan(&previous); err != nil {
		return "", norm(err)
	}
	if previous == name {
		return previous, nil
	}
	if _, err := tx.Exec(ctx,
		`UPDATE passkey_credentials SET device_name = $3 WHERE id = $1 AND user_id = $2`,
		credentialID, userID, name); err != nil {
		return "", err
	}
	return previous, tx.Commit(ctx)
}

// RevokedCredential is what a revoke removed, kept for the audit row and for
// telling the passkey provider the credential is gone.
type RevokedCredential struct {
	ID         int64
	Name       string
	AAGUID     []byte
	UserHandle []byte
}

// Revoke deletes a credential, refusing to remove the account's last one.
//
// With no password to fall back on, removing the final passkey is not an
// inconvenience — it is a permanently unreachable account. The account's
// credential rows are locked (FOR UPDATE) before they are counted, and the
// count and the delete run in one transaction, so two concurrent revokes
// serialize and cannot both pass the check and leave zero.
//
// A credential that is not the account's own is ErrNotFound, checked before the
// last-credential rule so the answer cannot reveal that another id exists.
func (d *DB) Revoke(ctx context.Context, userID, credentialID int64) (*RevokedCredential, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// FOR UPDATE cannot be combined with an aggregate, so lock the rows and
	// count them here.
	rows, err := tx.Query(ctx,
		`SELECT id, COALESCE(device_name, ''), COALESCE(aaguid::text, ''), user_handle
		   FROM passkey_credentials WHERE user_id = $1 ORDER BY id FOR UPDATE`, userID)
	if err != nil {
		return nil, err
	}
	var (
		n      int
		target *RevokedCredential
	)
	for rows.Next() {
		var c RevokedCredential
		var aaguid string
		if err := rows.Scan(&c.ID, &c.Name, &aaguid, &c.UserHandle); err != nil {
			rows.Close()
			return nil, err
		}
		n++
		if c.ID == credentialID {
			c.AAGUID = passkey.ParseAAGUID(aaguid)
			target = &c
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if target == nil {
		return nil, ErrNotFound
	}
	if n <= 1 {
		return nil, ErrLastCredential
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM passkey_credentials WHERE id = $1 AND user_id = $2`, credentialID, userID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return target, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
