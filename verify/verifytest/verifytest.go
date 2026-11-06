// Package verifytest mints Portiko-shaped tokens against an in-process key, so
// an API's tests can exercise verify without running a provider.
package verifytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/Kolonnade/Portiko/verify"
)

const (
	// Audience is the audience test access tokens carry.
	Audience = "api"
	// KeyID is the kid of the provider's signing key.
	KeyID = "test-key"
)

// Provider is a fake issuer: a signing key, a discovery document and a key set
// served over httptest.
type Provider struct {
	key     *ecdsa.PrivateKey
	srv     *httptest.Server
	fetches atomic.Int64
}

// NewProvider starts a fake issuer, closed when the test ends.
func NewProvider(t testing.TB) *Provider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("verifytest: generating key: %v", err)
	}
	p := &Provider{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": p.Issuer(), "jwks_uri": p.JWKSURL()})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		p.fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: KeyID, Algorithm: string(jose.ES256), Use: "sig"},
		}})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// Close stops the server.
func (p *Provider) Close() { p.srv.Close() }

// Issuer is the provider's issuer URL.
func (p *Provider) Issuer() string { return p.srv.URL }

// JWKSURL is where the key set is served.
func (p *Provider) JWKSURL() string { return p.srv.URL + "/jwks" }

// Client is an HTTP client for the provider's server.
func (p *Provider) Client() *http.Client { return p.srv.Client() }

// Fetches counts requests for the key set.
func (p *Provider) Fetches() int { return int(p.fetches.Load()) }

// KeySet is a fresh key-set cache pointed at the provider.
func (p *Provider) KeySet() *verify.KeySet { return verify.NewKeySet(p.JWKSURL(), p.Client()) }

// Verifier checks access tokens for Audience from this provider.
func (p *Provider) Verifier() *verify.Verifier {
	return verify.NewWithKeySet(p.Issuer(), Audience, p.KeySet(), verify.WithLeeway(verify.DefaultLeeway))
}

// AccessToken signs an access token for sub, shaped like the provider's. Each
// mutate function may change or delete claims before signing.
func (p *Provider) AccessToken(t testing.TB, sub string, mutate ...func(map[string]any)) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss":       p.Issuer(),
		"sub":       sub,
		"aud":       []any{Audience},
		"exp":       now.Add(15 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"jti":       "tok-" + sub,
		"client_id": Audience,
		"sid":       "sid-" + sub,
		"apv":       "1.0",
	}
	for _, m := range mutate {
		m(claims)
	}
	return p.Sign(t, "JWT", KeyID, claims)
}

// IDToken signs an ID token for sub: the claims an access token must not carry.
func (p *Provider) IDToken(t testing.TB, sub string) string {
	t.Helper()
	now := time.Now()
	return p.Sign(t, "JWT", KeyID, map[string]any{
		"iss":       p.Issuer(),
		"sub":       sub,
		"aud":       []any{Audience},
		"exp":       now.Add(15 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"azp":       Audience,
		"nonce":     "nonce",
		"at_hash":   "at-hash",
		"c_hash":    "c-hash",
		"auth_time": now.Unix(),
	})
}

// RefreshToken returns an opaque refresh token.
func (p *Provider) RefreshToken(t testing.TB) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("verifytest: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Sign signs claims with the provider's key, typ header typ and key id kid. An
// empty kid leaves the header without one.
func (p *Provider) Sign(t testing.TB, typ, kid string, claims map[string]any) string {
	t.Helper()
	opts := &jose.SignerOptions{}
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: &jose.JSONWebKey{Key: p.key, KeyID: kid}}, opts)
	if err != nil {
		t.Fatalf("verifytest: signer: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("verifytest: claims: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("verifytest: signing: %v", err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("verifytest: serializing: %v", err)
	}
	return s
}
