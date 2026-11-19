// Package session holds the relying party's own session: the server-side record
// of a signed-in browser, plus the cookie that points at it.
//
// Tokens stay here, on the server. The browser only ever holds an opaque
// identifier, so a cross-site script cannot read a credential that outlives the
// page.
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"
)

// ErrNotFound is returned for an unknown or expired session id.
var ErrNotFound = errors.New("session: not found")

// Session is one signed-in browser at one relying party.
type Session struct {
	ID      string
	Subject string
	Email   string
	Name    string
	Avatar  string // emoji from the accounts profile; empty until chosen
	SID     string // the accounts SSO session this sign-in came from
	// ProfileVersion is the updated_at of the profile this session shows. A
	// profile update only applies when it is newer, so updates arriving out of
	// order — a pushed event and a refreshed token — never regress it.
	ProfileVersion int64
	AccessToken    string
	RefreshToken   string
	// IDToken is the raw ID token from the provider. It stays on the server and
	// is sent back as id_token_hint when the person signs out at the provider.
	IDToken      string
	AccessExpiry time.Time
	ExpiresAt    time.Time
}

// Expired reports whether the session itself has lapsed.
func (s *Session) Expired() bool { return time.Now().After(s.ExpiresAt) }

// AccessExpired reports whether the access token needs refreshing. The minute of
// slack means a request that is about to be made does not race the expiry.
func (s *Session) AccessExpired() bool { return time.Now().Add(time.Minute).After(s.AccessExpiry) }

// Store persists sessions. Use pgstore (rp/session/pgstore) in production;
// MemoryStore is for tests and single-process development.
type Store interface {
	Get(ctx context.Context, id string) (*Session, error)
	Put(ctx context.Context, s *Session) error
	Delete(ctx context.Context, id string) error
}

// LogoutStore is a Store that can end sessions on the accounts service's
// instruction. A site needs it to honor a sign-out made at the accounts
// service, which arrives as a back-channel logout token.
type LogoutStore interface {
	Store
	// DeleteForLogout ends the subject's sessions that came from SSO session
	// sid, or all of the subject's sessions when sid is empty. Sessions stored
	// without a sid predate it and are ended either way. It reports how many
	// sessions it ended.
	DeleteForLogout(ctx context.Context, subject, sid string) (int, error)
}

// ProfileStore is a Store that can apply a profile change pushed by the
// accounts service to every session of a subject.
type ProfileStore interface {
	Store
	// UpdateProfile sets name and avatar on the subject's sessions whose
	// ProfileVersion is older than version, and reports how many it changed.
	UpdateProfile(ctx context.Context, subject, name, avatar string, version int64) (int, error)
}

// MemoryStore is an in-process Store. It pins the app to one replica, so it is
// development-only — the same constraint that made the accounts service move its
// WebAuthn challenges into Postgres.
type MemoryStore struct {
	mu sync.RWMutex
	m  map[string]*Session
}

// NewMemoryStore returns an empty in-process store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{m: map[string]*Session{}} }

func (s *MemoryStore) Get(_ context.Context, id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.m[id]
	if !ok || sess.Expired() {
		return nil, ErrNotFound
	}
	// A copy: a caller that edits the session it read must not change the stored
	// one without calling Put, and must not race another request doing the same.
	cp := *sess
	return &cp, nil
}

func (s *MemoryStore) Put(_ context.Context, sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *sess
	s.m[sess.ID] = &cp
	return nil
}

func (s *MemoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
	return nil
}

// DeleteForLogout implements LogoutStore.
func (s *MemoryStore) DeleteForLogout(_ context.Context, subject, sid string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, sess := range s.m {
		if sess.Subject != subject {
			continue
		}
		if sid == "" || sess.SID == "" || sess.SID == sid {
			delete(s.m, id)
			n++
		}
	}
	return n, nil
}

// UpdateProfile implements ProfileStore.
func (s *MemoryStore) UpdateProfile(_ context.Context, subject, name, avatar string, version int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, sess := range s.m {
		if sess.Subject == subject && sess.ProfileVersion < version {
			sess.Name, sess.Avatar, sess.ProfileVersion = name, avatar, version
			n++
		}
	}
	return n, nil
}

// NewID returns a 32-byte random session identifier, URL-safe and unpadded so it
// needs no escaping in a Set-Cookie header.
func NewID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CookieName is the relying party's session cookie.
const CookieName = "accounts_rp_session"

// SetCookie writes the session cookie.
//
// SameSite=Lax, deliberately. Strict would suppress the cookie on the inbound
// redirect back from the accounts service, breaking sign-in on the very first
// hop. Lax still blocks cross-site POSTs, which is the case that matters.
func SetCookie(w http.ResponseWriter, id string, expires time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    id,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie expires the session cookie.
func ClearCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}
