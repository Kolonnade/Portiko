// Package pgstore is a session.Store in PostgreSQL, so a site's sessions
// survive a restart and are shared by every replica.
//
// It implements session.LogoutStore and session.ProfileStore as well, so
// back-channel logout and pushed profile changes keep working.
//
// Nothing a session holds is stored in the clear. The session id (the cookie's
// value) is stored only as a SHA-256 hash, so a copy of the table cannot be
// replayed as cookies. The tokens, email, name and avatar are sealed with
// AES-256-GCM under a key the site configures, bound to the row they belong
// to. Only what the store must query on is plain: the subject (an opaque
// identifier), the provider's sid, the profile version and the expiry.
package pgstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Kolonnade/Portiko/rp/session"
)

// DefaultTable is the table sessions are kept in when Config.Table is empty.
const DefaultTable = "portiko_rp_sessions"

// KeySize is the length of a sealing key: AES-256.
const KeySize = 32

// Config configures a Store.
type Config struct {
	// Pool is the site's database. Required.
	Pool *pgxpool.Pool
	// Key seals the session contents. Exactly 32 random bytes, the same on
	// every replica and stable across restarts, or every session stops opening
	// and everyone is signed out. Required. Generate one with
	// `openssl rand -hex 32` and decode it.
	Key []byte
	// OldKeys are earlier keys, tried when Key does not open a row. Put a key
	// here when replacing it; rows are resealed under Key the next time they
	// are written, and the old key can go once SessionTTL has passed.
	OldKeys [][]byte
	// Table is the table name, optionally schema-qualified. Defaults to
	// DefaultTable.
	Table string
}

// Store is a session.Store, session.LogoutStore and session.ProfileStore in
// PostgreSQL.
type Store struct {
	pool  *pgxpool.Pool
	seal  cipher.AEAD
	open  []cipher.AEAD
	table string
}

var (
	_ session.LogoutStore  = (*Store)(nil)
	_ session.ProfileStore = (*Store)(nil)
)

var tableName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}(\.[a-z_][a-z0-9_]{0,62})?$`)

// New returns a store. Call Migrate once before using it.
func New(cfg Config) (*Store, error) {
	if cfg.Pool == nil {
		return nil, errors.New("pgstore: Pool is required")
	}
	table := cfg.Table
	if table == "" {
		table = DefaultTable
	}
	if !tableName.MatchString(table) {
		return nil, fmt.Errorf("pgstore: %q is not a plain lowercase table name", table)
	}
	seal, err := aead(cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("pgstore: Key: %w", err)
	}
	s := &Store{pool: cfg.Pool, seal: seal, open: []cipher.AEAD{seal}, table: table}
	for i, k := range cfg.OldKeys {
		a, err := aead(k)
		if err != nil {
			return nil, fmt.Errorf("pgstore: OldKeys[%d]: %w", i, err)
		}
		s.open = append(s.open, a)
	}
	return s, nil
}

func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Migrate creates the table and its indexes if they do not exist. It is safe to
// call on every start and from several replicas at once.
func (s *Store) Migrate(ctx context.Context) error {
	t := s.table
	// The lock serializes replicas starting together: CREATE ... IF NOT EXISTS
	// is not safe against itself running concurrently.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "pgstore:"+t); err != nil {
		return err
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS ` + t + ` (
			id_hash         TEXT PRIMARY KEY,
			subject         TEXT NOT NULL,
			sid             TEXT NOT NULL DEFAULT '',
			profile_version BIGINT NOT NULL DEFAULT 0,
			sealed          BYTEA NOT NULL,
			expires_at      TIMESTAMPTZ NOT NULL,
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS ` + indexName(t, "subject") + ` ON ` + t + ` (subject)`,
		`CREATE INDEX IF NOT EXISTS ` + indexName(t, "expires") + ` ON ` + t + ` (expires_at)`,
	} {
		if _, err := tx.Exec(ctx, q); err != nil {
			return fmt.Errorf("pgstore: migrate: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// indexName names an index after its table, without the schema: an index lives
// in its table's schema and may not be qualified.
func indexName(table, suffix string) string {
	for i := len(table) - 1; i >= 0; i-- {
		if table[i] == '.' {
			table = table[i+1:]
			break
		}
	}
	return table + "_" + suffix
}

// sealed is what goes inside the ciphertext: every field the store does not
// need to query on.
type sealed struct {
	Email        string    `json:"email,omitempty"`
	Name         string    `json:"name,omitempty"`
	Avatar       string    `json:"avatar,omitempty"`
	AccessToken  string    `json:"at,omitempty"`
	RefreshToken string    `json:"rt,omitempty"`
	IDToken      string    `json:"it,omitempty"`
	AccessExpiry time.Time `json:"ax"`
}

func hashID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// sealRow encrypts the fields, bound to the row's id hash so a sealed value
// copied to another row does not open there.
func (s *Store) sealRow(idHash string, v sealed) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, s.seal.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.seal.Seal(nonce, nonce, plain, []byte(idHash)), nil
}

func (s *Store) openRow(idHash string, blob []byte) (sealed, error) {
	var v sealed
	for _, a := range s.open {
		n := a.NonceSize()
		if len(blob) < n {
			break
		}
		plain, err := a.Open(nil, blob[:n], blob[n:], []byte(idHash))
		if err != nil {
			continue
		}
		return v, json.Unmarshal(plain, &v)
	}
	return v, errors.New("pgstore: no configured key opens this session")
}

// Get implements session.Store. An expired session, and one no configured key
// opens, is ErrNotFound: the person signs in again.
func (s *Store) Get(ctx context.Context, id string) (*session.Session, error) {
	h := hashID(id)
	var (
		sess session.Session
		blob []byte
	)
	err := s.pool.QueryRow(ctx,
		`SELECT subject, sid, profile_version, sealed, expires_at FROM `+s.table+
			` WHERE id_hash = $1 AND expires_at > now()`, h).
		Scan(&sess.Subject, &sess.SID, &sess.ProfileVersion, &blob, &sess.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, session.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	v, err := s.openRow(h, blob)
	if err != nil {
		slog.WarnContext(ctx, "pgstore: a session could not be opened; treating it as signed out", "err", err)
		return nil, session.ErrNotFound
	}
	sess.ID = id
	sess.Email, sess.Name, sess.Avatar = v.Email, v.Name, v.Avatar
	sess.AccessToken, sess.RefreshToken, sess.IDToken = v.AccessToken, v.RefreshToken, v.IDToken
	sess.AccessExpiry = v.AccessExpiry
	return &sess, nil
}

// Put implements session.Store: it creates the session or replaces it.
func (s *Store) Put(ctx context.Context, sess *session.Session) error {
	h := hashID(sess.ID)
	blob, err := s.sealRow(h, sealed{
		Email: sess.Email, Name: sess.Name, Avatar: sess.Avatar,
		AccessToken: sess.AccessToken, RefreshToken: sess.RefreshToken, IDToken: sess.IDToken,
		AccessExpiry: sess.AccessExpiry,
	})
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO `+s.table+` (id_hash, subject, sid, profile_version, sealed, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (id_hash) DO UPDATE
		    SET subject = EXCLUDED.subject, sid = EXCLUDED.sid, profile_version = EXCLUDED.profile_version,
		        sealed = EXCLUDED.sealed, expires_at = EXCLUDED.expires_at, updated_at = now()`,
		h, sess.Subject, sess.SID, sess.ProfileVersion, blob, sess.ExpiresAt)
	return err
}

// Delete implements session.Store.
func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM `+s.table+` WHERE id_hash = $1`, hashID(id))
	return err
}

// DeleteForLogout implements session.LogoutStore.
func (s *Store) DeleteForLogout(ctx context.Context, subject, sid string) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM `+s.table+` WHERE subject = $1 AND ($2 = '' OR sid = '' OR sid = $2)`, subject, sid)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// UpdateProfile implements session.ProfileStore. Each older session is opened,
// changed and resealed under Key, with its row locked, so a concurrent Put or
// a second update cannot interleave.
func (s *Store) UpdateProfile(ctx context.Context, subject, name, avatar string, version int64) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx,
		`SELECT id_hash, sealed FROM `+s.table+`
		  WHERE subject = $1 AND profile_version < $2 AND expires_at > now()
		  FOR UPDATE`, subject, version)
	if err != nil {
		return 0, err
	}
	type row struct {
		h    string
		blob []byte
	}
	var found []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.h, &r.blob); err != nil {
			rows.Close()
			return 0, err
		}
		found = append(found, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range found {
		v, err := s.openRow(r.h, r.blob)
		if err != nil {
			continue // Unopenable: Get will treat it as signed out anyway.
		}
		v.Name, v.Avatar = name, avatar
		blob, err := s.sealRow(r.h, v)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE `+s.table+` SET sealed = $2, profile_version = $3, updated_at = now() WHERE id_hash = $1`,
			r.h, blob, version); err != nil {
			return 0, err
		}
		n++
	}
	return n, tx.Commit(ctx)
}

// Prune deletes expired sessions and reports how many.
func (s *Store) Prune(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM `+s.table+` WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RunPruner calls Prune every interval until ctx is done. Run it in a
// goroutine; several replicas running it at once is harmless.
func (s *Store) RunPruner(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := s.Prune(ctx); err != nil {
				slog.WarnContext(ctx, "pgstore: pruning expired sessions", "err", err)
			} else if n > 0 {
				slog.InfoContext(ctx, "pgstore: pruned expired sessions", "count", n)
			}
		}
	}
}
