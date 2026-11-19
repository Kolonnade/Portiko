package pgstore_test

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Kolonnade/Portiko/rp/session"
	"github.com/Kolonnade/Portiko/rp/session/pgstore"
)

func databaseURL() string {
	if v := os.Getenv("TEST_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://localhost:5432/portiko_test?sslmode=disable"
}

// newStore gives each test its own table in a schema of its own, so it neither
// collides with the provider's tests (which reset the public schema) nor with
// another test here.
func newStore(t *testing.T, key []byte, old ...[]byte) (*pgstore.Store, *pgxpool.Pool, string) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL())
	if err != nil {
		t.Skipf("test database unavailable: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("test database unavailable: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS rp_session_test`); err != nil {
		t.Fatal(err)
	}
	table := "rp_session_test." + strings.ToLower(strings.NewReplacer("/", "_", "-", "_").Replace(t.Name()))
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS `+table); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS `+table) })
	s, err := pgstore.New(pgstore.Config{Pool: pool, Key: key, OldKeys: old, Table: table})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate is not idempotent: %v", err)
	}
	return s, pool, table
}

func key(b byte) []byte { return bytes.Repeat([]byte{b}, pgstore.KeySize) }

func sample(id, subject, sid string) *session.Session {
	return &session.Session{
		ID: id, Subject: subject, SID: sid, Email: "person@example.com", Name: "Pat", Avatar: "fox",
		ProfileVersion: 10, AccessToken: "access-SECRET", RefreshToken: "refresh-SECRET", IDToken: "id-SECRET",
		AccessExpiry: time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		ExpiresAt:    time.Now().Add(24 * time.Hour).UTC().Truncate(time.Microsecond),
	}
}

func TestPutGetDelete(t *testing.T) {
	s, _, _ := newStore(t, key(1))
	ctx := context.Background()
	want := sample("cookie-1", "sub-1", "sid-1")
	if err := s.Put(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "cookie-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.Subject != want.Subject || got.SID != want.SID || got.Email != want.Email ||
		got.Name != want.Name || got.Avatar != want.Avatar || got.ProfileVersion != want.ProfileVersion ||
		got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken || got.IDToken != want.IDToken ||
		!got.AccessExpiry.Equal(want.AccessExpiry) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, want)
	}

	// Put replaces.
	want.AccessToken = "rotated"
	if err := s.Put(ctx, want); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(ctx, "cookie-1"); got.AccessToken != "rotated" {
		t.Errorf("after a second Put: %q", got.AccessToken)
	}

	if err := s.Delete(ctx, "cookie-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "cookie-1"); err != session.ErrNotFound {
		t.Errorf("after Delete: %v", err)
	}
	if _, err := s.Get(ctx, "never"); err != session.ErrNotFound {
		t.Errorf("unknown id: %v", err)
	}
}

func TestExpiryAndPrune(t *testing.T) {
	s, _, _ := newStore(t, key(1))
	ctx := context.Background()
	old := sample("old", "sub", "")
	old.ExpiresAt = time.Now().Add(-time.Minute)
	live := sample("live", "sub", "")
	for _, x := range []*session.Session{old, live} {
		if err := s.Put(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Get(ctx, "old"); err != session.ErrNotFound {
		t.Errorf("an expired session was returned: %v", err)
	}
	n, err := s.Prune(ctx)
	if err != nil || n != 1 {
		t.Fatalf("Prune = %d, %v; want 1", n, err)
	}
	if _, err := s.Get(ctx, "live"); err != nil {
		t.Errorf("Prune removed a live session: %v", err)
	}
}

func TestDeleteForLogout(t *testing.T) {
	s, _, _ := newStore(t, key(1))
	ctx := context.Background()
	for _, x := range []*session.Session{
		sample("a-sid1", "alice", "sid-1"),
		sample("a-sid2", "alice", "sid-2"),
		sample("a-nosid", "alice", ""),
		sample("b-sid1", "bob", "sid-1"),
	} {
		if err := s.Put(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	// One SSO session: its own sessions, and those stored without a sid.
	n, err := s.DeleteForLogout(ctx, "alice", "sid-1")
	if err != nil || n != 2 {
		t.Fatalf("by sid: %d, %v; want 2", n, err)
	}
	if _, err := s.Get(ctx, "a-sid2"); err != nil {
		t.Error("another SSO session of the same subject was ended")
	}
	if _, err := s.Get(ctx, "b-sid1"); err != nil {
		t.Error("another subject with the same sid was ended")
	}
	// No sid: every session of the subject.
	if n, _ := s.DeleteForLogout(ctx, "alice", ""); n != 1 {
		t.Errorf("all of the subject: %d, want 1", n)
	}
	if _, err := s.Get(ctx, "b-sid1"); err != nil {
		t.Error("bob was signed out")
	}
}

// Updates arriving out of order (a pushed event and a refreshed token) never
// move a session back to an older profile.
func TestUpdateProfileOrdering(t *testing.T) {
	s, _, _ := newStore(t, key(1))
	ctx := context.Background()
	if err := s.Put(ctx, sample("one", "alice", "")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, sample("two", "alice", "")); err != nil {
		t.Fatal(err)
	}
	if n, err := s.UpdateProfile(ctx, "alice", "Newer", "owl", 20); err != nil || n != 2 {
		t.Fatalf("newer: %d, %v", n, err)
	}
	if n, _ := s.UpdateProfile(ctx, "alice", "Older", "cat", 15); n != 0 {
		t.Errorf("an older profile changed %d sessions", n)
	}
	if n, _ := s.UpdateProfile(ctx, "alice", "Same", "cat", 20); n != 0 {
		t.Errorf("the same version changed %d sessions", n)
	}
	got, err := s.Get(ctx, "one")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Newer" || got.Avatar != "owl" || got.ProfileVersion != 20 || got.AccessToken != "access-SECRET" {
		t.Errorf("after updates: %+v", got)
	}
}

// What is in the table, read straight from the database, must give away neither
// a token, the address nor a usable cookie.
func TestNothingSecretIsStoredInTheClear(t *testing.T) {
	s, pool, table := newStore(t, key(1))
	ctx := context.Background()
	if err := s.Put(ctx, sample("cookie-value", "sub", "sid")); err != nil {
		t.Fatal(err)
	}
	var dump string
	if err := pool.QueryRow(ctx, `SELECT string_agg(t::text, '|') FROM `+table+` t`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	_ = pool.QueryRow(ctx, `SELECT sealed FROM `+table).Scan(&sealed)
	for _, secret := range []string{"SECRET", "person@example.com", "Pat", "cookie-value"} {
		if strings.Contains(dump, secret) || bytes.Contains(sealed, []byte(secret)) {
			t.Errorf("%q is readable in the table", secret)
		}
	}
}

func TestKeys(t *testing.T) {
	ctx := context.Background()
	if _, err := pgstore.New(pgstore.Config{Pool: &pgxpool.Pool{}, Key: []byte("short")}); err == nil {
		t.Error("a short key was accepted")
	}
	if _, err := pgstore.New(pgstore.Config{Pool: &pgxpool.Pool{}, Key: key(1), Table: "x; DROP TABLE y"}); err == nil {
		t.Error("an unsafe table name was accepted")
	}

	s1, pool, table := newStore(t, key(1))
	if err := s1.Put(ctx, sample("c", "sub", "")); err != nil {
		t.Fatal(err)
	}
	// A different key cannot open it: signed out, not an error.
	wrong, _ := pgstore.New(pgstore.Config{Pool: pool, Key: key(2), Table: table})
	if _, err := wrong.Get(ctx, "c"); err != session.ErrNotFound {
		t.Errorf("a wrong key: %v", err)
	}
	// Rotating: the old key still opens it, and a write reseals it under the new.
	rotated, _ := pgstore.New(pgstore.Config{Pool: pool, Key: key(2), OldKeys: [][]byte{key(1)}, Table: table})
	got, err := rotated.Get(ctx, "c")
	if err != nil {
		t.Fatalf("old key during rotation: %v", err)
	}
	if err := rotated.Put(ctx, got); err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Get(ctx, "c"); err != nil {
		t.Errorf("not resealed under the new key: %v", err)
	}
	// A sealed value moved to another row does not open there.
	if err := rotated.Put(ctx, sample("d", "sub", "")); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE `+table+` SET sealed = (SELECT sealed FROM `+table+` x WHERE x.id_hash <> `+table+`.id_hash LIMIT 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.Get(ctx, "d"); err != session.ErrNotFound {
		t.Errorf("a swapped sealed value opened: %v", err)
	}
}
