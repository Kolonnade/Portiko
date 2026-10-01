package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Kolonnade/Portiko/internal/keys"
)

// Errors a rotation reports to the operator driving it.
var (
	// ErrKeyNotPending is returned when activating something that is not waiting
	// to be activated.
	ErrKeyNotPending = errors.New("store: that key is not pending")
	// ErrKeyNotRetiring is returned when retiring something that is still
	// signing, or already gone.
	ErrKeyNotRetiring = errors.New("store: that key is not retiring")
	// ErrRotationInFlight is returned when a second rotation is started while one
	// is still half-done.
	ErrRotationInFlight = errors.New("store: a rotation is already in flight")
	// ErrTooSoon is returned when a rotation phase would run before the caches it
	// exists to wait for have turned over.
	ErrTooSoon = errors.New("store: too soon")
)

// KeyInfo is a signing key's public state, for the operator listing.
//
// It deliberately carries no key material: seeing where a rotation stands must
// not require the secret that decrypts the keys.
type KeyInfo struct {
	KID         string
	Algorithm   string
	State       keys.State
	Sealed      bool
	CreatedAt   time.Time
	ActivatedAt *time.Time
	RetiredAt   *time.Time
}

// LoadKeys reads and decrypts every non-retired signing key.
func (d *DB) LoadKeys(ctx context.Context, sealer keys.Sealer) ([]*keys.Key, error) {
	type stored struct {
		kid, state string
		blob       []byte
	}
	rows, err := d.pool.Query(ctx,
		`SELECT kid, private_key, state FROM signing_keys
		  WHERE state <> 'retired' ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	var loaded []stored
	for rows.Next() {
		var s stored
		if err := rows.Scan(&s.kid, &s.blob, &s.state); err != nil {
			rows.Close()
			return nil, err
		}
		loaded = append(loaded, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]*keys.Key, 0, len(loaded))
	for _, s := range loaded {
		pem, err := sealer.Unseal(s.kid, s.blob)
		if err != nil {
			return nil, err
		}
		k, err := keys.DecodePEM(s.kid, pem, keys.State(s.state))
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// SaveKey persists a signing key, sealed.
func (d *DB) SaveKey(ctx context.Context, sealer keys.Sealer, k *keys.Key) error {
	pem, err := k.EncodePEM()
	if err != nil {
		return err
	}
	blob, err := sealer.Seal(k.KID, pem)
	if err != nil {
		return err
	}
	jwk, err := json.Marshal(k.JWK())
	if err != nil {
		return err
	}
	// The private key is written once and the upsert never replaces it. Replacing
	// it would re-key an id that verifiers have already cached under the old
	// public half, and every token signed by the old one would stop verifying.
	_, err = d.pool.Exec(ctx,
		`INSERT INTO signing_keys (kid, algorithm, private_key, public_key_jwk, state, activated_at)
		 VALUES ($1, 'ES256', $2, $3, $4, CASE WHEN $4 = 'active' THEN now() END)
		 ON CONFLICT (kid) DO UPDATE SET state = EXCLUDED.state`,
		k.KID, blob, jwk, string(k.State))
	return err
}

// EnsureActiveKey loads the key ring, generating and persisting a first key if
// the deployment has none.
//
// Keys must outlive the process: an ephemeral key means every restart
// invalidates every outstanding token, and every relying party's cached JWKS
// goes stale at the same moment.
func (d *DB) EnsureActiveKey(ctx context.Context, sealer keys.Sealer) (*keys.Ring, error) {
	loaded, err := d.LoadKeys(ctx, sealer)
	if err != nil {
		return nil, err
	}
	if len(loaded) == 0 {
		k, err := keys.Generate()
		if err != nil {
			return nil, err
		}
		k.State = keys.StateActive
		if err := d.SaveKey(ctx, sealer, k); err != nil {
			return nil, err
		}
		loaded = []*keys.Key{k}
	}
	return keys.NewRing(loaded)
}

// Keys lists every signing key, retired ones included, oldest first.
func (d *DB) Keys(ctx context.Context) ([]KeyInfo, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT kid, algorithm, state, private_key, created_at, activated_at, retired_at
		   FROM signing_keys ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyInfo
	for rows.Next() {
		var k KeyInfo
		var state string
		var blob []byte
		if err := rows.Scan(&k.KID, &k.Algorithm, &state, &blob,
			&k.CreatedAt, &k.ActivatedAt, &k.RetiredAt); err != nil {
			return nil, err
		}
		k.State = keys.State(state)
		k.Sealed = keys.Sealed(blob)
		out = append(out, k)
	}
	return out, rows.Err()
}

// SealStoredKeys encrypts in place every key still held as plaintext, leaving
// each one's id — and therefore every token it has already signed — untouched.
//
// It returns the ids it sealed. Run again it seals nothing and reports nothing,
// so it is safe to leave in a deploy script.
func (d *DB) SealStoredKeys(ctx context.Context, sealer keys.Sealer) ([]string, error) {
	all, err := d.storedKeys(ctx)
	if err != nil {
		return nil, err
	}
	var sealed []string
	for _, s := range all {
		if keys.Sealed(s.blob) {
			continue
		}
		// Parse before writing. A row that is neither sealed nor valid PEM is
		// something this command must not overwrite: whatever it is, what is
		// there is the only copy.
		if _, err := keys.DecodePEM(s.kid, s.blob, keys.StatePending); err != nil {
			return sealed, fmt.Errorf("store: sealing %s: %w", s.kid, err)
		}
		blob, err := sealer.Seal(s.kid, s.blob)
		if err != nil {
			return sealed, err
		}
		if err := d.writeStoredKey(ctx, s.kid, blob); err != nil {
			return sealed, err
		}
		sealed = append(sealed, s.kid)
	}
	return sealed, nil
}

// UnsealStoredKeys writes every sealed key back as plaintext.
//
// It exists for exactly one situation: rolling back to a release that cannot
// read sealed keys. It puts signing keys into the database in the clear, which is
// the problem the rest of this file exists to fix, so it is a deliberate operator
// action and never part of a normal deploy.
func (d *DB) UnsealStoredKeys(ctx context.Context, sealer keys.Sealer) ([]string, error) {
	all, err := d.storedKeys(ctx)
	if err != nil {
		return nil, err
	}
	var done []string
	for _, s := range all {
		if !keys.Sealed(s.blob) {
			continue
		}
		pem, err := sealer.Unseal(s.kid, s.blob)
		if err != nil {
			return done, err
		}
		if err := d.writeStoredKey(ctx, s.kid, pem); err != nil {
			return done, err
		}
		done = append(done, s.kid)
	}
	return done, nil
}

type storedKey struct {
	kid  string
	blob []byte
}

// storedKeys drains every stored key before anything is written, so that a
// re-encryption pass is never iterating a live query it is also updating.
func (d *DB) storedKeys(ctx context.Context) ([]storedKey, error) {
	rows, err := d.pool.Query(ctx, `SELECT kid, private_key FROM signing_keys ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storedKey
	for rows.Next() {
		var s storedKey
		if err := rows.Scan(&s.kid, &s.blob); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) writeStoredKey(ctx context.Context, kid string, blob []byte) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE signing_keys SET private_key = $2 WHERE kid = $1`, kid, blob)
	return err
}

// BeginRotation creates the next signing key, published but not yet signing.
//
// It refuses while a previous rotation is unfinished. Two keys waiting in the
// same phase is how an operator loses track of which one the service is about to
// sign with, and the state machine has no way to ask.
func (d *DB) BeginRotation(ctx context.Context, sealer keys.Sealer) (*keys.Key, error) {
	var inflight int
	if err := d.pool.QueryRow(ctx,
		`SELECT count(*) FROM signing_keys WHERE state IN ('pending', 'retiring')`).Scan(&inflight); err != nil {
		return nil, err
	}
	if inflight > 0 {
		return nil, ErrRotationInFlight
	}
	k, err := keys.Generate() // Generate returns a pending key.
	if err != nil {
		return nil, err
	}
	if err := d.SaveKey(ctx, sealer, k); err != nil {
		return nil, err
	}
	return k, nil
}

// ActivateKey makes a pending key the signing key and moves the current one to
// retiring.
//
// force skips the wait for verifiers' key-set caches to pick the new key up. That
// is for an emergency: a key believed to be compromised must stop signing now,
// and some verifiers briefly failing is the better outcome.
//
// Both changes happen in one transaction, and the demotion comes first: the
// schema allows exactly one active key, so promoting first would collide with it.
func (d *DB) ActivateKey(ctx context.Context, kid string, force bool) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var state string
	var createdAt time.Time
	if err := tx.QueryRow(ctx,
		`SELECT state, created_at FROM signing_keys WHERE kid = $1 FOR UPDATE`, kid).
		Scan(&state, &createdAt); err != nil {
		return norm(err)
	}
	if keys.State(state) != keys.StatePending {
		return fmt.Errorf("%w (it is %s)", ErrKeyNotPending, state)
	}
	if wait := keys.PublishDelay - time.Since(createdAt); wait > 0 && !force {
		return fmt.Errorf("%w: %s has been published for %s; wait another %s so cached key sets pick it up",
			ErrTooSoon, kid, time.Since(createdAt).Round(time.Second), wait.Round(time.Second))
	}

	if _, err := tx.Exec(ctx,
		`UPDATE signing_keys SET state = 'retiring' WHERE state = 'active'`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE signing_keys SET state = 'active', activated_at = now() WHERE kid = $1`, kid); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RetireKey drops a retiring key from the published key set.
//
// force skips the wait for outstanding tokens to expire, which invalidates every
// token that key signed — the right thing when the key is compromised, and a
// self-inflicted outage otherwise.
func (d *DB) RetireKey(ctx context.Context, kid string, force bool) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var state string
	// When this key stopped signing is when its successor started, so the wait is
	// measured from the successor's activation, not from anything on this row.
	var stoppedSigningAt *time.Time
	if err := tx.QueryRow(ctx,
		`SELECT s.state, (SELECT max(activated_at) FROM signing_keys WHERE state = 'active')
		   FROM signing_keys s WHERE s.kid = $1 FOR UPDATE`, kid).
		Scan(&state, &stoppedSigningAt); err != nil {
		return norm(err)
	}
	if keys.State(state) != keys.StateRetiring {
		return fmt.Errorf("%w (it is %s)", ErrKeyNotRetiring, state)
	}
	if stoppedSigningAt != nil {
		if wait := keys.RetireDelay - time.Since(*stoppedSigningAt); wait > 0 && !force {
			return fmt.Errorf("%w: %s stopped signing %s ago; wait another %s so its tokens expire first",
				ErrTooSoon, kid, time.Since(*stoppedSigningAt).Round(time.Second), wait.Round(time.Second))
		}
	}
	if _, err := tx.Exec(ctx,
		`UPDATE signing_keys SET state = 'retired', retired_at = now() WHERE kid = $1`, kid); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
