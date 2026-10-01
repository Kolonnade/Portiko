// Package provider is Portiko's identity provider: passkey ceremonies, a set of
// signed-in accounts per browser, and an OpenID Connect provider built on
// zitadel/oidc that issues audience-scoped tokens to every site.
package provider

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"

	"github.com/Kolonnade/Portiko/internal/accounts"
	"github.com/Kolonnade/Portiko/internal/config"
	"github.com/Kolonnade/Portiko/internal/keys"
	"github.com/Kolonnade/Portiko/internal/mailer"
	"github.com/Kolonnade/Portiko/internal/passkey"
	"github.com/Kolonnade/Portiko/internal/store"
	"github.com/Kolonnade/Portiko/profile"
)

// Config is the provider's runtime configuration.
type Config = config.Config

// LoadConfig reads configuration from the environment, reporting every problem
// at once.
func LoadConfig() (*Config, error) { return config.Load() }

// Options are the extension points a deployment may fill.
type Options struct {
	// Profiles supplies how an account is presented to sites. Nil uses the
	// built-in display name and emoji avatar.
	Profiles profile.Source
	// Mailer delivers one-time codes. Nil uses SMTP when configured, otherwise
	// the log.
	Mailer mailer.Mailer
}

// Provider is a running identity provider.
type Provider struct {
	cfg     *Config
	db      *store.DB
	handler http.Handler
}

// New connects to the database, loads or creates the signing key, and builds
// the HTTP surface. Configuration mistakes fail here rather than at a person's
// first sign-in.
func New(ctx context.Context, cfg *Config, opts Options) (*Provider, error) {
	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Provider, error) {
		db.Close()
		return nil, err
	}

	wa, err := passkey.New(cfg)
	if err != nil {
		return fail(err)
	}
	ring, err := db.EnsureActiveKey(ctx, keys.SealerFor(cfg.CryptoKey, cfg.DevInsecure))
	if err != nil {
		return fail(err)
	}

	m := opts.Mailer
	if m == nil {
		m = &mailer.Stdout{ServiceName: cfg.ServiceName}
		if cfg.SMTPHost != "" {
			m = &mailer.SMTP{
				Host: cfg.SMTPHost, Port: cfg.SMTPPort,
				Username: cfg.SMTPUsername, Password: cfg.SMTPPassword,
				From: cfg.EmailFrom, ServiceName: cfg.ServiceName,
			}
		}
	}
	profiles := opts.Profiles
	if profiles == nil {
		profiles = builtinProfiles{db: db}
	}

	auth := &Auth{cfg: cfg, db: db, svc: accounts.New(cfg, db, wa, m), ring: ring, profiles: profiles}
	st := &storage{db: db, ring: ring, cfg: cfg, profiles: profiles, ended: auth.notifyLogout}

	opOpts := []op.Option{
		op.WithCustomEndpoints(
			op.NewEndpoint("oauth/authorize"),
			op.NewEndpoint("oauth/token"),
			op.NewEndpoint("oauth/userinfo"),
			op.NewEndpoint("oauth/revoke"),
			op.NewEndpoint("oauth/end_session"),
			op.NewEndpoint(".well-known/jwks.json"),
		),
		op.WithCustomIntrospectionEndpoint(op.NewEndpoint("oauth/introspect")),
	}
	if cfg.DevInsecure {
		opOpts = append(opOpts, op.WithAllowInsecure())
	}
	oidcProvider, err := op.NewProvider(&op.Config{
		CryptoKey:                         cfg.CryptoKey,
		DefaultLogoutRedirectURI:          cfg.Issuer + "/signin",
		CodeMethodS256:                    true,
		AuthMethodPost:                    true,
		GrantTypeRefreshToken:             true,
		SupportedUILocales:                []language.Tag{language.English},
		SupportedScopes:                   []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeOfflineAccess},
		BackChannelLogoutSupported:        true,
		BackChannelLogoutSessionSupported: true,
	}, st, op.StaticIssuer(cfg.Issuer), opOpts...)
	if err != nil {
		return fail(fmt.Errorf("provider: building the OpenID provider: %w", err))
	}
	auth.op = oidcProvider

	pages, err := NewPages(cfg, auth)
	if err != nil {
		return fail(err)
	}
	health := func(w http.ResponseWriter, r *http.Request) {
		// A health check that always says ok never catches anything; touch the database.
		if err := db.Pool().Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"degraded","database":"unreachable"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}

	return &Provider{
		cfg: cfg,
		db:  db,
		handler: Router(Deps{
			OpenID:    oidcProvider.HttpHandler(),
			Discovery: &Discovery{cfg: cfg},
			Auth:      auth,
			Login:     &Login{auth: auth},
			Pages:     pages,
			Health:    health,
		}),
	}, nil
}

// Handler is the provider's complete HTTP surface.
func (p *Provider) Handler() http.Handler { return p.handler }

// DB exposes the store, for operator commands and tests.
func (p *Provider) DB() *store.DB { return p.db }

// Close releases the database.
func (p *Provider) Close() { p.db.Close() }

// Sweep removes lapsed ceremonies, codes and authorization requests until ctx
// ends.
func (p *Provider) Sweep(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := p.db.SweepExpired(ctx); err != nil {
				slog.Warn("sweeping expired rows", "err", err)
			} else if n > 0 {
				slog.Info("swept expired rows", "n", n)
			}
		}
	}
}
