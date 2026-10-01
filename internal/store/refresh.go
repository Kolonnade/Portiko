package store

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"
)

// RefreshToken is a stored refresh token.
type RefreshToken struct {
	Hash      string
	FamilyID  string
	ClientID  string
	UserID    int64
	Subject   string
	Scopes    []string
	SID       string
	AuthTime  time.Time
	AMR       []string
	ExpiresAt time.Time
}

// RefreshTokenTTL is the lifetime of a refresh token.
const RefreshTokenTTL = 30 * 24 * time.Hour

// RefreshReuseGrace is how long a rotated-away token may still be presented.
//
// A page that fires several requests as its access token expires can present
// the same refresh token more than once before the first rotation reaches it.
// Inside this window that is a race, not a theft. Outside it, it is treated as a
// theft.
const RefreshReuseGrace = 30 * time.Second

// ErrRefreshReused is returned when a rotated-away token is presented outside
// the grace window. The whole family has been revoked by then.
var ErrRefreshReused = errors.New("store: refresh token reused")

// CreateRefreshToken stores a token for a grant and returns its plaintext. An
// empty FamilyID starts a new family.
func (d *DB) CreateRefreshToken(ctx context.Context, rt RefreshToken) (string, error) {
	token, err := RandomToken(32)
	if err != nil {
		return "", err
	}
	if err := d.insertRefresh(ctx, d.pool, token, rt); err != nil {
		return "", err
	}
	return token, nil
}

func (d *DB) insertRefresh(ctx context.Context, q queryExecer, token string, rt RefreshToken) error {
	hash := HashToken(token)
	if rt.FamilyID == "" {
		rt.FamilyID = hash
	}
	if rt.AMR == nil {
		rt.AMR = []string{}
	}
	_, err := q.Exec(ctx,
		`INSERT INTO refresh_tokens
		   (token_hash, family_id, client_id, user_id, scope, sid, auth_time, amr, expires_at)
		 VALUES ($1, $2, $3, $4, $5, NULLIF($6,''), $7, $8, now() + $9::interval)`,
		hash, rt.FamilyID, rt.ClientID, rt.UserID, strings.Join(rt.Scopes, " "), rt.SID,
		rt.AuthTime, rt.AMR, RefreshTokenTTL.String())
	return err
}

// RefreshTokenByToken resolves a presented token for redemption.
//
// A token that was rotated away within the grace window is still honored. One
// presented after that — or one revoked for any other reason — revokes every
// token in its family and is refused, so a thief and the legitimate holder both
// have to sign in again and the theft becomes visible.
func (d *DB) RefreshTokenByToken(ctx context.Context, token string) (*RefreshToken, error) {
	var rt RefreshToken
	var scope string
	var revokedAt, rotatedAt *time.Time
	err := d.pool.QueryRow(ctx,
		`SELECT r.token_hash, r.family_id, r.client_id, r.user_id, u.subject, r.scope,
		        COALESCE(r.sid, ''), r.auth_time, r.amr, r.expires_at, r.revoked_at, r.rotated_at
		   FROM refresh_tokens r JOIN users u ON u.id = r.user_id
		  WHERE r.token_hash = $1 AND r.expires_at > now() AND u.active`, HashToken(token)).
		Scan(&rt.Hash, &rt.FamilyID, &rt.ClientID, &rt.UserID, &rt.Subject, &scope,
			&rt.SID, &rt.AuthTime, &rt.AMR, &rt.ExpiresAt, &revokedAt, &rotatedAt)
	if err != nil {
		return nil, norm(err)
	}
	rt.Scopes = strings.Fields(scope)

	if revokedAt == nil {
		return &rt, nil
	}
	if rotatedAt != nil && time.Since(*rotatedAt) <= RefreshReuseGrace {
		return &rt, nil
	}
	if _, err := d.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL`,
		rt.FamilyID); err != nil {
		return nil, err
	}
	if rotatedAt != nil {
		slog.WarnContext(ctx, "refresh token reused after rotation; family revoked",
			"client_id", rt.ClientID, "user_id", rt.UserID)
		d.Audit(ctx, AuditEvent{UserID: &rt.UserID, ClientID: rt.ClientID,
			Action: AuditRefreshReuse, Detail: map[string]any{"family": rt.FamilyID}})
	}
	return nil, ErrRefreshReused
}

// RotateRefreshToken marks a presented token as rotated and issues its
// successor in the same family.
func (d *DB) RotateRefreshToken(ctx context.Context, presented string, next RefreshToken) (string, error) {
	token, err := RandomToken(32)
	if err != nil {
		return "", err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := tx.QueryRow(ctx,
		`UPDATE refresh_tokens
		    SET revoked_at = COALESCE(revoked_at, now()), rotated_at = COALESCE(rotated_at, now())
		  WHERE token_hash = $1
		 RETURNING family_id`, HashToken(presented)).Scan(&next.FamilyID); err != nil {
		return "", norm(err)
	}
	if err := d.insertRefresh(ctx, tx, token, next); err != nil {
		return "", err
	}
	return token, tx.Commit(ctx)
}

// RevokeRefreshFamily revokes a presented token and every token in its family.
// An unknown token is not an error: revocation must not be usable to probe which
// tokens exist.
func (d *DB) RevokeRefreshFamily(ctx context.Context, token, clientID string) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now()
		  WHERE revoked_at IS NULL
		    AND family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = $1 AND client_id = $2)`,
		HashToken(token), clientID)
	return err
}

// RevokeRefreshForClient revokes an account's tokens at one client.
func (d *DB) RevokeRefreshForClient(ctx context.Context, userID int64, clientID string) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now()
		  WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL`, userID, clientID)
	return err
}

// ActiveClientIDs lists the clients holding a live refresh token for the user:
// the sites that currently have a session for them to keep up to date.
func (d *DB) ActiveClientIDs(ctx context.Context, userID int64) ([]string, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT client_id FROM refresh_tokens
		  WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()`, userID)
	if err != nil {
		return nil, err
	}
	return distinctClientIDs(rows)
}
