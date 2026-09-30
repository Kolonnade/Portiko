// Package verify checks tokens a relying party receives from anyone who is not
// the token endpoint: back-channel logout tokens, pushed security events, and
// bearer tokens on a site's own API. Those arrive from the network, so every
// check here assumes the token may be hostile.
package verify

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/Kolonnade/Portiko/protocol"
)

// KeySet fetches and caches the issuer's public keys.
//
// The rule that matters more than the caching: **at most one fetch per
// minInterval, whatever arrives.** A token carrying a random key id is otherwise
// a request amplifier pointed at the identity provider, because every unknown id
// looks like a rotation worth checking for. A genuinely new key after rotation is
// still picked up within one interval.
type KeySet struct {
	url    string
	client *http.Client

	mu          sync.Mutex
	keys        map[string]*jose.JSONWebKey
	fetchedAt   time.Time
	lastAttempt time.Time

	ttl         time.Duration
	minInterval time.Duration
}

// NewKeySet builds a cache for the key set at url.
func NewKeySet(url string, client *http.Client) *KeySet {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &KeySet{url: url, client: client, keys: map[string]*jose.JSONWebKey{},
		ttl: 15 * time.Minute, minInterval: time.Minute}
}

// SetMinInterval changes the refetch limit. Tests only.
func (k *KeySet) SetMinInterval(d time.Duration) { k.minInterval = d }

// Key returns the public key for kid.
func (k *KeySet) Key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	k.mu.Lock()
	key, ok := k.keys[kid]
	fresh := time.Since(k.fetchedAt) < k.ttl
	fetch := (!ok || !fresh) && time.Since(k.lastAttempt) >= k.minInterval
	if fetch {
		// Claimed under the lock, so concurrent callers cannot all decide to fetch.
		k.lastAttempt = time.Now()
	}
	k.mu.Unlock()

	if ok && fresh {
		return key, nil
	}
	if fetch {
		if err := k.refresh(ctx); err != nil && !ok {
			return nil, err
		}
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if key, ok := k.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("verify: no key for kid %q", kid)
}

func (k *KeySet) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("verify: fetching keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("verify: keys endpoint returned %s", resp.Status)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&set); err != nil {
		return fmt.Errorf("verify: decoding keys: %w", err)
	}
	keys := map[string]*jose.JSONWebKey{}
	for i := range set.Keys {
		jwk := set.Keys[i]
		// Only signing keys for the one algorithm this protocol permits. A key with
		// no id cannot be selected deterministically, and guessing is how the
		// wrong key gets used.
		if jwk.KeyID == "" || (jwk.Use != "" && jwk.Use != "sig") {
			continue
		}
		if _, ok := jwk.Key.(*ecdsa.PublicKey); !ok {
			continue
		}
		keys[jwk.KeyID] = &jwk
	}
	if len(keys) == 0 {
		return errors.New("verify: key set contained no usable keys")
	}
	k.mu.Lock()
	k.keys, k.fetchedAt = keys, time.Now()
	k.mu.Unlock()
	return nil
}

// Options are the checks applied to a token. None is optional.
type Options struct {
	Issuer   string
	Audience string // this relying party's client_id
	Keys     *KeySet
	Leeway   time.Duration
	// Type, when set, must equal the token's typ header, so one kind of token
	// cannot be replayed as another.
	Type string
}

// Claims is a verified token's payload.
type Claims struct {
	Subject         string
	Issuer          string
	Audience        string
	Email           string
	EmailVerified   bool
	Name            string
	Avatar          string
	SessionID       string
	UpdatedAt       int64
	Scope           string
	TokenID         string
	ProtocolVersion string
	AuthTime        time.Time
	ExpiresAt       time.Time
	Raw             map[string]any
}

// Token parses and verifies a compact JWS.
//
// The algorithm is pinned to ES256 rather than read from the header, the token
// must carry exactly one audience equal to Options.Audience, and expiry is
// required.
func Token(ctx context.Context, raw string, opts Options) (*Claims, error) {
	if opts.Issuer == "" || opts.Audience == "" || opts.Keys == nil {
		return nil, errors.New("verify: Issuer, Audience and Keys are all required")
	}
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("verify: parsing: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("verify: expected exactly one signature")
	}
	header := jws.Signatures[0].Header
	if opts.Type != "" {
		typ, _ := header.ExtraHeaders[jose.HeaderType].(string)
		if !strings.EqualFold(typ, opts.Type) {
			return nil, fmt.Errorf("verify: token type %q, want %q", typ, opts.Type)
		}
	}
	if header.KeyID == "" {
		return nil, errors.New("verify: token has no kid")
	}
	key, err := opts.Keys.Key(ctx, header.KeyID)
	if err != nil {
		return nil, err
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("verify: signature: %w", err)
	}

	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, fmt.Errorf("verify: claims: %w", err)
	}
	c := &Claims{
		Subject:         str(m, protocol.ClaimSubject),
		Issuer:          str(m, protocol.ClaimIssuer),
		Email:           str(m, protocol.ClaimEmail),
		Name:            str(m, protocol.ClaimName),
		Avatar:          str(m, protocol.ClaimAvatar),
		SessionID:       str(m, protocol.ClaimSessionID),
		Scope:           str(m, protocol.ClaimScope),
		TokenID:         str(m, protocol.ClaimJWTID),
		ProtocolVersion: str(m, protocol.ClaimProtocolVersion),
		Audience:        opts.Audience,
		Raw:             m,
	}
	if c.Issuer != opts.Issuer {
		return nil, fmt.Errorf("verify: issuer %q, want %q", c.Issuer, opts.Issuer)
	}
	// Exactly one audience. Membership alone would let the holder of a token
	// meant for two sites present it at either.
	switch aud := m[protocol.ClaimAudience].(type) {
	case string:
		if aud != opts.Audience {
			return nil, fmt.Errorf("verify: audience %q, want %q", aud, opts.Audience)
		}
	case []any:
		if len(aud) != 1 || aud[0] != opts.Audience {
			return nil, fmt.Errorf("verify: token must carry exactly the audience %q", opts.Audience)
		}
	default:
		return nil, errors.New("verify: token has no audience")
	}
	now := time.Now()
	exp, ok := num(m, protocol.ClaimExpiry)
	if !ok {
		return nil, errors.New("verify: token has no expiry")
	}
	c.ExpiresAt = time.Unix(exp, 0)
	if now.After(c.ExpiresAt.Add(opts.Leeway)) {
		return nil, errors.New("verify: token expired")
	}
	if iat, ok := num(m, protocol.ClaimIssuedAt); ok && time.Unix(iat, 0).After(now.Add(opts.Leeway)) {
		return nil, errors.New("verify: token issued in the future")
	}
	if c.Subject == "" {
		return nil, errors.New("verify: token has no subject")
	}
	if v, ok := m[protocol.ClaimEmailVerified].(bool); ok {
		c.EmailVerified = v
	}
	if v, ok := num(m, protocol.ClaimUpdatedAt); ok {
		c.UpdatedAt = v
	}
	if v, ok := num(m, protocol.ClaimAuthTime); ok {
		c.AuthTime = time.Unix(v, 0)
	}
	return c, nil
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func num(m map[string]any, k string) (int64, bool) {
	f, ok := m[k].(float64)
	return int64(f), ok
}
