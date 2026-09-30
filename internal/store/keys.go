package store

import (
	"context"
	"encoding/json"

	"github.com/Kolonnade/Portiko/internal/keys"
)

// LoadKeys reads every non-retired signing key.
func (d *DB) LoadKeys(ctx context.Context) ([]*keys.Key, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT kid, private_key_pem, state FROM signing_keys
		  WHERE state <> 'retired' ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*keys.Key
	for rows.Next() {
		var kid, state string
		var pem []byte
		if err := rows.Scan(&kid, &pem, &state); err != nil {
			return nil, err
		}
		k, err := keys.DecodePEM(kid, pem, keys.State(state))
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// SaveKey persists a signing key.
func (d *DB) SaveKey(ctx context.Context, k *keys.Key) error {
	pem, err := k.EncodePEM()
	if err != nil {
		return err
	}
	jwk, err := json.Marshal(k.JWK())
	if err != nil {
		return err
	}
	var activated any
	if k.State == keys.StateActive {
		activated = "now()"
	}
	_ = activated
	_, err = d.pool.Exec(ctx,
		`INSERT INTO signing_keys (kid, algorithm, private_key_pem, public_key_jwk, state, activated_at)
		 VALUES ($1, 'ES256', $2, $3, $4, CASE WHEN $4 = 'active' THEN now() END)
		 ON CONFLICT (kid) DO UPDATE SET state = EXCLUDED.state`,
		k.KID, pem, jwk, string(k.State))
	return err
}

// EnsureActiveKey loads the key ring, generating and persisting a first key if
// the deployment has none.
//
// Keys must outlive the process: an ephemeral key means every restart
// invalidates every outstanding token, and every relying party's cached JWKS
// goes stale at the same moment.
func (d *DB) EnsureActiveKey(ctx context.Context) (*keys.Ring, error) {
	loaded, err := d.LoadKeys(ctx)
	if err != nil {
		return nil, err
	}
	if len(loaded) == 0 {
		k, err := keys.Generate()
		if err != nil {
			return nil, err
		}
		k.State = keys.StateActive
		if err := d.SaveKey(ctx, k); err != nil {
			return nil, err
		}
		loaded = []*keys.Key{k}
	}
	return keys.NewRing(loaded)
}
