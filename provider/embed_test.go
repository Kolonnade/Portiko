package provider_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/Kolonnade/Portiko/internal/store"
	"github.com/Kolonnade/Portiko/provider"
)

// Migrate is safe on every start, records its place the way the golang-migrate
// CLI does, and refuses a schema the CLI left half-applied.
func TestMigrateIsRepeatableAndCLICompatible(t *testing.T) {
	h := newHarness(t) // resetSchema already migrated an empty schema
	ctx := context.Background()

	first, err := provider.Migrate(ctx, testDatabaseURL())
	if err != nil {
		t.Fatalf("migrating a current schema: %v", err)
	}
	var version int
	var dirty bool
	if err := h.db.Pool().QueryRow(ctx, `SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		t.Fatalf("reading schema_migrations: %v", err)
	}
	if version != first || dirty || version < 9 {
		t.Fatalf("schema_migrations = (%d, %v), Migrate said %d", version, dirty, first)
	}

	if _, err := h.db.Pool().Exec(ctx, `UPDATE schema_migrations SET dirty = true`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = h.db.Pool().Exec(ctx, `UPDATE schema_migrations SET dirty = false`) })
	if _, err := provider.Migrate(ctx, testDatabaseURL()); err == nil || !strings.Contains(err.Error(), "dirty") {
		t.Fatalf("a dirty schema must be refused, got %v", err)
	}
}

// RegisterClient leaves the client exactly as declared, including the URIs the
// CLI sets separately, and a second declaration replaces the first.
func TestRegisterClientDeclaresTheWholeClient(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	c := provider.Client{
		ID: "almanac", Secret: "s3cret", Audience: "https://almanac.example",
		RedirectURIs:         []string{"https://almanac.example/auth/callback"},
		FirstParty:           true,
		BackchannelLogoutURI: "https://almanac.example/auth/backchannel-logout",
		EventsURI:            "https://almanac.example/auth/events",
	}
	if err := h.p.RegisterClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := h.db.ClientByID(ctx, "almanac")
	if err != nil {
		t.Fatal(err)
	}
	want := store.Client{
		ClientID: "almanac", SecretHash: store.HashToken("s3cret"), Audience: c.Audience,
		DisplayName: "almanac", RedirectURIs: c.RedirectURIs, PostLogoutRedirectURIs: []string{},
		AllowedScopes: []string{"openid", "profile", "offline_access"}, TrustTier: "first_party",
		ApplicationType: "web", Active: true,
		BackchannelLogoutURI: c.BackchannelLogoutURI, EventsURI: c.EventsURI,
	}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("registered client:\n got %+v\nwant %+v", *got, want)
	}

	// Redeclared without the events URI and as third-party: both stick.
	c.EventsURI, c.FirstParty = "", false
	if err := h.p.RegisterClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, _ = h.db.ClientByID(ctx, "almanac")
	if got.EventsURI != "" || got.TrustTier != "third_party" || got.BackchannelLogoutURI == "" {
		t.Fatalf("redeclared client: %+v", *got)
	}

	for _, bad := range []provider.Client{
		{Audience: "https://x", RedirectURIs: []string{"https://x/cb"}, Secret: "s"},
		{ID: "x", RedirectURIs: []string{"https://x/cb"}, Secret: "s"},
		{ID: "x", Audience: "https://x", Secret: "s"},
		{ID: "x", Audience: "https://x", RedirectURIs: []string{"https://x/cb"}},
	} {
		if err := h.p.RegisterClient(ctx, bad); err == nil {
			t.Errorf("RegisterClient(%+v) should fail", bad)
		}
	}
	native := provider.Client{ID: "app", Audience: "https://app", RedirectURIs: []string{"app:/cb"}, Native: true}
	if err := h.p.RegisterClient(ctx, native); err != nil {
		t.Fatalf("a native client needs no secret: %v", err)
	}
}
