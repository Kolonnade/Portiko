package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Verifier checks bearer access tokens for one API: one issuer, one audience,
// one cached key set. It is safe for concurrent use.
type Verifier struct {
	opts Options
}

type config struct {
	leeway time.Duration
	client *http.Client
}

// Option configures a Verifier.
type Option func(*config)

// WithLeeway sets the allowed clock skew. The default is DefaultLeeway.
func WithLeeway(d time.Duration) Option { return func(c *config) { c.leeway = d } }

// WithHTTPClient sets the client used for discovery and for fetching keys.
func WithHTTPClient(client *http.Client) Option { return func(c *config) { c.client = client } }

func newConfig(opts []Option) config {
	c := config{leeway: DefaultLeeway}
	for _, o := range opts {
		o(&c)
	}
	if c.client == nil {
		c.client = &http.Client{Timeout: 10 * time.Second}
	}
	return c
}

// New discovers the issuer's key set and returns a Verifier for audience. The
// discovery document must name exactly issuer.
func New(ctx context.Context, issuer, audience string, opts ...Option) (*Verifier, error) {
	if issuer == "" || audience == "" {
		return nil, fmt.Errorf("%w: issuer and audience are required", ErrConfig)
	}
	cfg := newConfig(opts)
	url := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeySet, err)
	}
	resp, err := cfg.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: discovery: %v", ErrKeySet, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: discovery returned %s", ErrKeySet, resp.Status)
	}
	var disc struct {
		Issuer  string `json:"issuer"`
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&disc); err != nil {
		return nil, fmt.Errorf("%w: decoding discovery: %v", ErrKeySet, err)
	}
	if disc.Issuer != issuer {
		return nil, fmt.Errorf("%w: discovery names %q, want %q", ErrIssuer, disc.Issuer, issuer)
	}
	if disc.JwksURI == "" {
		return nil, fmt.Errorf("%w: discovery has no jwks_uri", ErrKeySet)
	}
	return &Verifier{opts: Options{
		Issuer: issuer, Audience: audience, Keys: NewKeySet(disc.JwksURI, cfg.client), Leeway: cfg.leeway,
	}}, nil
}

// NewWithKeySet returns a Verifier that uses keys directly, with no discovery.
// WithHTTPClient has no effect here; keys already has its client.
func NewWithKeySet(issuer, audience string, keys *KeySet, opts ...Option) *Verifier {
	cfg := newConfig(opts)
	return &Verifier{opts: Options{Issuer: issuer, Audience: audience, Keys: keys, Leeway: cfg.leeway}}
}

// Verify checks a bearer access token. See AccessToken.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	return AccessToken(ctx, raw, v.opts)
}

// Issuer is the issuer this Verifier accepts.
func (v *Verifier) Issuer() string { return v.opts.Issuer }

// Audience is the audience this Verifier accepts.
func (v *Verifier) Audience() string { return v.opts.Audience }
