// Package keys manages the ES256 signing keys and the key set derived from
// them.
//
// Asymmetric signing is what makes federation possible at all: a relying party
// holding the public key can verify a token but cannot mint one. A shared HMAC
// secret would let any site that verifies tokens forge them for every other site.
package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Kolonnade/Portiko/protocol"
)

// State is a signing key's position in the rotation lifecycle.
//
// The sequence matters: a new key must be published before it signs anything
// (so verifiers have it cached), and a retired key must stay published until
// every token it signed has expired.
type State string

const (
	StatePending  State = "pending"  // in the key set, not signing
	StateActive   State = "active"   // signing; exactly one at a time
	StateRetiring State = "retiring" // not signing, still in the key set
	StateRetired  State = "retired"  // gone from the key set
)

// Key is one signing key.
type Key struct {
	KID     string
	Private *ecdsa.PrivateKey
	State   State
}

// Generate creates a new P-256 key with a KID derived from its public point, so
// the same key always gets the same identifier.
func Generate() (*Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keys: generating: %w", err)
	}
	pub, err := priv.PublicKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("keys: encoding public key: %w", err)
	}
	sum := sha256.Sum256(pub.Bytes())
	return &Key{
		KID:     base64.RawURLEncoding.EncodeToString(sum[:16]),
		Private: priv,
		State:   StatePending,
	}, nil
}

// EncodePEM serializes the private key for storage.
func (k *Key) EncodePEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(k.Private)
	if err != nil {
		return nil, fmt.Errorf("keys: marshalling: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// DecodePEM restores a key from storage.
func DecodePEM(kid string, data []byte, state State) (*Key, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("keys: %s: not PEM", kid)
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keys: %s: %w", kid, err)
	}
	return &Key{KID: kid, Private: priv, State: state}, nil
}

// JWK renders the public half as a JSON Web Key, for storage alongside it.
func (k *Key) JWK() map[string]any {
	jwk := jose.JSONWebKey{Key: &k.Private.PublicKey, KeyID: k.KID, Algorithm: protocol.SigningAlg, Use: "sig"}
	raw, _ := jwk.MarshalJSON()
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// Ring holds the keys in play.
type Ring struct {
	mu     sync.RWMutex
	keys   []*Key
	active *Key
}

// NewRing builds a ring, which must contain exactly one active key.
func NewRing(keys []*Key) (*Ring, error) {
	r := &Ring{keys: keys}
	for _, k := range keys {
		if k.State == StateActive {
			if r.active != nil {
				return nil, fmt.Errorf("keys: more than one active key")
			}
			r.active = k
		}
	}
	if r.active == nil {
		return nil, fmt.Errorf("keys: no active signing key")
	}
	return r, nil
}

func (r *Ring) activeKey() *Key {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active
}

// SigningKey returns the active key in the shape zitadel/oidc signs with.
func (r *Ring) SigningKey() op.SigningKey { return signingKey{r.activeKey()} }

// PublicKeys returns every key a verifier might still need: everything except
// retired. Dropping a key the moment it stops signing would invalidate tokens
// that are still inside their lifetime.
func (r *Ring) PublicKeys() []op.Key {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]op.Key, 0, len(r.keys))
	for _, k := range r.keys {
		if k.State != StateRetired {
			out = append(out, publicKey{k})
		}
	}
	return out
}

type signingKey struct{ k *Key }

func (s signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (s signingKey) Key() any                                    { return s.k.Private }
func (s signingKey) ID() string                                  { return s.k.KID }

type publicKey struct{ k *Key }

func (p publicKey) ID() string                         { return p.k.KID }
func (p publicKey) Algorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (p publicKey) Use() string                        { return "sig" }
func (p publicKey) Key() any                           { return &p.k.Private.PublicKey }

// LogoutTokenTTL is short: a logout token is delivered at once, server to
// server, and a stale one has no business being accepted.
const LogoutTokenTTL = 2 * time.Minute

// EventTokenTTL bounds how long a pushed security event is accepted.
const EventTokenTTL = 2 * time.Minute

// SignLogout mints an OpenID Connect back-channel logout token for one client.
//
// It is addressed to the client_id, like an ID token, and told apart from one by
// its typ header and by what it carries: an events claim naming the logout
// event, and never a nonce. sid, when set, limits the logout to the sessions
// that came from that account's session in one browser.
func (r *Ring) SignLogout(issuer, clientID, subject, sid string) (string, error) {
	claims := r.baseClaims(issuer, clientID, subject, LogoutTokenTTL)
	claims[protocol.ClaimEvents] = map[string]any{protocol.EventBackchannelLogout: map[string]any{}}
	if sid != "" {
		claims[protocol.ClaimSessionID] = sid
	}
	return r.sign(protocol.TypeLogoutToken, claims)
}

// SignEvent mints a Security Event Token (RFC 8417) carrying one event for one
// client. Like a logout token it is addressed to the client_id and identified
// by its typ header and events claim, and never carries a nonce.
func (r *Ring) SignEvent(issuer, clientID, subject, eventType string, event map[string]any) (string, error) {
	claims := r.baseClaims(issuer, clientID, subject, EventTokenTTL)
	claims[protocol.ClaimEvents] = map[string]any{eventType: event}
	return r.sign(protocol.TypeEventToken, claims)
}

func (r *Ring) baseClaims(issuer, clientID, subject string, ttl time.Duration) map[string]any {
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	now := time.Now()
	return map[string]any{
		protocol.ClaimIssuer:   issuer,
		protocol.ClaimSubject:  subject,
		protocol.ClaimAudience: clientID,
		protocol.ClaimIssuedAt: now.Unix(),
		protocol.ClaimExpiry:   now.Add(ttl).Unix(),
		protocol.ClaimJWTID:    base64.RawURLEncoding.EncodeToString(jti),
	}
}

func (r *Ring) sign(typ string, claims map[string]any) (string, error) {
	active := r.activeKey()
	if active == nil {
		return "", fmt.Errorf("keys: no active signing key")
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: &jose.JSONWebKey{Key: active.Private, KeyID: active.KID}},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		return "", fmt.Errorf("keys: creating signer: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("keys: signing: %w", err)
	}
	return obj.CompactSerialize()
}
