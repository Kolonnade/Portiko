package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Kolonnade/Portiko/internal/mailer"
	"github.com/Kolonnade/Portiko/internal/store"
	"github.com/Kolonnade/Portiko/migrations"
)

// Mailer delivers the provider's messages: the one-time code that starts a
// ceremony, and the notice that a passkey was added to an existing account.
// Implement it to send through something other than SMTP; both methods are
// required, because a deployment that adds passkeys silently gives the holder
// no way to notice a compromised mailbox.
type Mailer = mailer.Mailer

// PasskeyNotice describes a passkey just added to an account that already
// existed. Authenticator is empty when the passkey's provider is unknown, which
// is the common case, so a message must read sensibly without it.
type PasskeyNotice = mailer.PasskeyNotice

// Migrate brings the database at databaseURL up to the schema this version of
// the provider needs, and returns the version it ends at. Call it before New.
//
// It is safe to call on every start and from several replicas at once, and it
// keeps the same schema_migrations table as the golang-migrate CLI, so either
// can be used on the same database.
func Migrate(ctx context.Context, databaseURL string) (int, error) {
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return 0, fmt.Errorf("provider: connecting to migrate: %w", err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	return migrations.Apply(ctx, conn)
}

// Client is a site or app that signs people in with this provider.
type Client struct {
	// ID is the OAuth client_id.
	ID string
	// Secret authenticates a confidential client. Leave it empty for a native
	// app, which authenticates with PKCE alone; Native must then be set.
	Secret string
	// Audience is the site's origin, e.g. https://example.com. It is the
	// audience of the client's access tokens and is shown on the home page.
	Audience string
	// DisplayName is what people see; it defaults to ID.
	DisplayName string
	// RedirectURIs are the exact callback URLs the client may use. Required.
	RedirectURIs []string
	// PostLogoutRedirectURIs are where RP-initiated logout may return to.
	PostLogoutRedirectURIs []string
	// Scopes the client may be granted; empty means openid, profile and
	// offline_access.
	Scopes []string
	// FirstParty marks a client this deployment operates: it skips consent and
	// is listed on the signed-in home page.
	FirstParty bool
	// Native marks a public app (RFC 8252) rather than a web site.
	Native bool
	// BackchannelLogoutURI receives a logout token when someone signs out.
	BackchannelLogoutURI string
	// EventsURI receives pushed security events, such as a profile change.
	EventsURI string
}

// RegisterClient creates the client, or replaces it with exactly this
// declaration, so a site can register itself on every start. It does not
// reactivate a client an operator has switched off.
func (p *Provider) RegisterClient(ctx context.Context, c Client) error {
	var problems []string
	if c.ID == "" {
		problems = append(problems, "ID is required")
	}
	if c.Audience == "" {
		problems = append(problems, "Audience is required")
	}
	if len(c.RedirectURIs) == 0 {
		problems = append(problems, "at least one RedirectURI is required")
	}
	if c.Secret == "" && !c.Native {
		problems = append(problems, "a web client needs a Secret; a public client must set Native")
	}
	if len(problems) > 0 {
		return errors.New("provider: registering client " + c.ID + ": " + strings.Join(problems, "; "))
	}
	sc := store.Client{
		ClientID: c.ID, Audience: c.Audience, DisplayName: c.DisplayName,
		RedirectURIs: c.RedirectURIs, PostLogoutRedirectURIs: c.PostLogoutRedirectURIs,
		AllowedScopes: c.Scopes, TrustTier: "third_party", ApplicationType: "web",
		BackchannelLogoutURI: c.BackchannelLogoutURI, EventsURI: c.EventsURI,
	}
	if sc.DisplayName == "" {
		sc.DisplayName = c.ID
	}
	if len(sc.AllowedScopes) == 0 {
		sc.AllowedScopes = []string{"openid", "profile", "offline_access"}
	}
	if c.FirstParty {
		sc.TrustTier = "first_party"
	}
	if c.Native {
		sc.ApplicationType = "native"
	}
	return p.db.PutClient(ctx, sc, c.Secret)
}
