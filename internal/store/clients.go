package store

import (
	"context"
	"slices"
)

// Client is a registered relying party.
type Client struct {
	ClientID               string
	SecretHash             string // empty for a public client, which authenticates with PKCE alone
	Audience               string // the site's origin; shown on the home page
	DisplayName            string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	AllowedScopes          []string
	TrustTier              string
	ApplicationType        string
	Active                 bool
	// BackchannelLogoutURI receives a logout token when a user signs out.
	BackchannelLogoutURI string
	// EventsURI receives pushed security events, such as a profile change.
	EventsURI string
}

// FirstParty reports whether the client is operated by this deployment.
func (c *Client) FirstParty() bool { return c.TrustTier == "first_party" }

// AllowsScope reports whether the client may be granted scope.
func (c *Client) AllowsScope(scope string) bool { return slices.Contains(c.AllowedScopes, scope) }

const clientColumns = `client_id, COALESCE(client_secret_hash, ''), audience, display_name, redirect_uris,
	post_logout_redirect_uris, allowed_scopes, trust_tier, application_type, active,
	COALESCE(backchannel_logout_uri, ''), COALESCE(events_uri, '')`

// ClientByID loads an active client.
func (d *DB) ClientByID(ctx context.Context, clientID string) (*Client, error) {
	var c Client
	err := d.pool.QueryRow(ctx, `SELECT `+clientColumns+` FROM oauth_clients WHERE client_id = $1 AND active`, clientID).
		Scan(&c.ClientID, &c.SecretHash, &c.Audience, &c.DisplayName, &c.RedirectURIs,
			&c.PostLogoutRedirectURIs, &c.AllowedScopes, &c.TrustTier, &c.ApplicationType, &c.Active,
			&c.BackchannelLogoutURI, &c.EventsURI)
	if err != nil {
		return nil, norm(err)
	}
	return &c, nil
}

// FirstPartyClients lists the active first-party clients, for the signed-in home
// page's links to them. Third-party clients are left out on purpose: listing
// them would read as an endorsement of sites nobody here operates.
func (d *DB) FirstPartyClients(ctx context.Context) ([]Client, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT client_id, audience, display_name FROM oauth_clients
		  WHERE active AND trust_tier = 'first_party' ORDER BY display_name, client_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		c := Client{TrustTier: "first_party", Active: true}
		if err := rows.Scan(&c.ClientID, &c.Audience, &c.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpsertClient registers or updates a client. An empty secret registers a
// public client. Empty scope and post-logout lists keep what is stored.
func (d *DB) UpsertClient(ctx context.Context, c Client, secret string) error {
	var hash any
	if secret != "" {
		hash = HashToken(secret)
	}
	if c.ApplicationType == "" {
		c.ApplicationType = "web"
	}
	scopes := c.AllowedScopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "offline_access"}
	}
	postLogout := c.PostLogoutRedirectURIs
	if postLogout == nil {
		postLogout = []string{}
	}
	_, err := d.pool.Exec(ctx,
		`INSERT INTO oauth_clients
		   (client_id, client_secret_hash, audience, display_name, redirect_uris, trust_tier,
		    allowed_scopes, post_logout_redirect_uris, application_type)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (client_id) DO UPDATE SET
		   client_secret_hash        = EXCLUDED.client_secret_hash,
		   audience                  = EXCLUDED.audience,
		   display_name              = EXCLUDED.display_name,
		   redirect_uris             = EXCLUDED.redirect_uris,
		   trust_tier                = EXCLUDED.trust_tier,
		   allowed_scopes            = EXCLUDED.allowed_scopes,
		   post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
		   application_type          = EXCLUDED.application_type`,
		c.ClientID, hash, c.Audience, c.DisplayName, c.RedirectURIs, c.TrustTier, scopes, postLogout, c.ApplicationType)
	return err
}

// SetBackchannelLogoutURI records where a client receives logout tokens; an
// empty uri stops notifying it.
func (d *DB) SetBackchannelLogoutURI(ctx context.Context, clientID, uri string) error {
	return d.setClientColumn(ctx, "backchannel_logout_uri", clientID, uri)
}

// SetEventsURI records where a client receives pushed security events; an empty
// uri stops them.
func (d *DB) SetEventsURI(ctx context.Context, clientID, uri string) error {
	return d.setClientColumn(ctx, "events_uri", clientID, uri)
}

// SetAllowedScopes replaces the scopes a client may be granted.
func (d *DB) SetAllowedScopes(ctx context.Context, clientID string, scopes []string) error {
	tag, err := d.pool.Exec(ctx, `UPDATE oauth_clients SET allowed_scopes = $2 WHERE client_id = $1`, clientID, scopes)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) setClientColumn(ctx context.Context, column, clientID, value string) error {
	tag, err := d.pool.Exec(ctx,
		`UPDATE oauth_clients SET `+column+` = NULLIF($2, '') WHERE client_id = $1`, clientID, value)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// LogoutRecipients returns the active clients among ids that registered a
// back-channel logout URI.
func (d *DB) LogoutRecipients(ctx context.Context, ids []string) ([]Client, error) {
	return d.recipients(ctx, "backchannel_logout_uri", ids)
}

// EventRecipients returns the active clients among ids that registered an
// events URI.
func (d *DB) EventRecipients(ctx context.Context, ids []string) ([]Client, error) {
	return d.recipients(ctx, "events_uri", ids)
}

func (d *DB) recipients(ctx context.Context, column string, ids []string) ([]Client, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := d.pool.Query(ctx,
		`SELECT client_id, `+column+` FROM oauth_clients
		  WHERE active AND `+column+` IS NOT NULL AND client_id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		var c Client
		var uri string
		if err := rows.Scan(&c.ClientID, &uri); err != nil {
			return nil, err
		}
		if column == "events_uri" {
			c.EventsURI = uri
		} else {
			c.BackchannelLogoutURI = uri
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PutClient registers or replaces a client in full, in one statement: unlike
// UpsertClient it also writes the server-to-server URIs, so a client declared
// in code at startup ends up exactly as declared. It never changes active, so
// a client an operator switched off stays off across restarts.
func (d *DB) PutClient(ctx context.Context, c Client, secret string) error {
	var hash any
	if secret != "" {
		hash = HashToken(secret)
	}
	nullable := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	if c.PostLogoutRedirectURIs == nil {
		c.PostLogoutRedirectURIs = []string{}
	}
	_, err := d.pool.Exec(ctx,
		`INSERT INTO oauth_clients
		   (client_id, client_secret_hash, audience, display_name, redirect_uris, trust_tier,
		    allowed_scopes, post_logout_redirect_uris, application_type,
		    backchannel_logout_uri, events_uri)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (client_id) DO UPDATE SET
		   client_secret_hash        = EXCLUDED.client_secret_hash,
		   audience                  = EXCLUDED.audience,
		   display_name              = EXCLUDED.display_name,
		   redirect_uris             = EXCLUDED.redirect_uris,
		   trust_tier                = EXCLUDED.trust_tier,
		   allowed_scopes            = EXCLUDED.allowed_scopes,
		   post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
		   application_type          = EXCLUDED.application_type,
		   backchannel_logout_uri    = EXCLUDED.backchannel_logout_uri,
		   events_uri                = EXCLUDED.events_uri`,
		c.ClientID, hash, c.Audience, c.DisplayName, c.RedirectURIs, c.TrustTier,
		c.AllowedScopes, c.PostLogoutRedirectURIs, c.ApplicationType,
		nullable(c.BackchannelLogoutURI), nullable(c.EventsURI))
	return err
}
