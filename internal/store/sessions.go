package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Session is one signed-in account in one browser.
//
// A browser is identified by its cookie, which is stored only as a hash. It may
// hold several sessions, one per account, each numbered in sign-in order. The
// number is a handle for "which of my accounts", never an identity: it is
// resolved to a user on every request, and it is never reused while the browser
// lives, so a stale link carrying it cannot land on somebody else's account.
type Session struct {
	UserID          int64
	SID             string // public per-account session id, carried to sites as "sid"
	Ordinal         int
	IsDefault       bool
	AuthenticatedAt time.Time // when the ceremony behind this session happened
	AMR             []string
	CreatedAt       time.Time
	LastSeenAt      time.Time
	ExpiresAt       time.Time
}

// SessionTTL is the sliding lifetime of a session.
const SessionTTL = 30 * 24 * time.Hour

// MaxAccountsPerBrowser caps the sessions one browser may hold.
const MaxAccountsPerBrowser = 5

// ErrTooManyAccounts is returned when a browser already holds the maximum.
var ErrTooManyAccounts = errors.New("store: too many accounts in this browser")

// NewBrowserToken returns a fresh cookie value naming a browser.
func NewBrowserToken() (string, error) { return RandomToken(32) }

const sessionColumns = `user_id, sid, ordinal, is_default, authenticated_at, amr, created_at, last_seen_at, expires_at`

func scanSession(row pgx.Row) (*Session, error) {
	var s Session
	if err := row.Scan(&s.UserID, &s.SID, &s.Ordinal, &s.IsDefault, &s.AuthenticatedAt, &s.AMR,
		&s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt); err != nil {
		return nil, norm(err)
	}
	return &s, nil
}

// AddSession records that a ceremony just signed userID in on the browser named
// by browserToken, creating the browser when browserToken is empty. It returns
// the browser token to set as the cookie.
//
// Signing in again as an account the browser already holds keeps its number and
// refreshes when it authenticated; signing in as a new account adds it with the
// next number. The first account in a browser is its default.
func (d *DB) AddSession(ctx context.Context, browserToken string, userID int64, amr []string, userAgent, ip string) (string, *Session, error) {
	if browserToken == "" {
		t, err := NewBrowserToken()
		if err != nil {
			return "", nil, err
		}
		browserToken = t
	}
	hash := HashToken(browserToken)

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO browsers (browser_hash) VALUES ($1) ON CONFLICT (browser_hash) DO NOTHING`, hash); err != nil {
		return "", nil, fmt.Errorf("store: creating browser: %w", err)
	}
	// Lock the browser row so two tabs adding accounts at once take numbers in turn.
	var next int
	if err := tx.QueryRow(ctx,
		`SELECT next_ordinal FROM browsers WHERE browser_hash = $1 FOR UPDATE`, hash).Scan(&next); err != nil {
		return "", nil, norm(err)
	}
	if amr == nil {
		amr = []string{}
	}

	existing, err := scanSession(tx.QueryRow(ctx,
		`UPDATE sso_sessions
		    SET authenticated_at = now(), amr = $3, last_seen_at = now(),
		        expires_at = now() + $4::interval, user_agent = $5, ip = NULLIF($6,'')::inet
		  WHERE browser_hash = $1 AND user_id = $2
		 RETURNING `+sessionColumns, hash, userID, amr, SessionTTL.String(), userAgent, ip))
	if err == nil {
		return browserToken, existing, tx.Commit(ctx)
	}
	if !errors.Is(err, ErrNotFound) {
		return "", nil, err
	}

	var held int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM sso_sessions WHERE browser_hash = $1 AND expires_at > now()`, hash).Scan(&held); err != nil {
		return "", nil, err
	}
	if held >= MaxAccountsPerBrowser {
		return "", nil, ErrTooManyAccounts
	}
	sid, err := RandomToken(16)
	if err != nil {
		return "", nil, err
	}
	s, err := scanSession(tx.QueryRow(ctx,
		`INSERT INTO sso_sessions
		   (browser_hash, user_id, sid, ordinal, is_default, authenticated_at, amr, user_agent, ip, expires_at)
		 VALUES ($1, $2, $3, $4,
		         NOT EXISTS (SELECT 1 FROM sso_sessions WHERE browser_hash = $1 AND is_default),
		         now(), $5, $6, NULLIF($7,'')::inet, now() + $8::interval)
		 RETURNING `+sessionColumns,
		hash, userID, sid, next, amr, userAgent, ip, SessionTTL.String()))
	if err != nil {
		return "", nil, fmt.Errorf("store: adding session: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE browsers SET next_ordinal = next_ordinal + 1 WHERE browser_hash = $1`, hash); err != nil {
		return "", nil, err
	}
	return browserToken, s, tx.Commit(ctx)
}

// Sessions returns the live sessions of the browser named by browserToken, in
// number order, sliding each one's expiry forward.
func (d *DB) Sessions(ctx context.Context, browserToken string) ([]Session, error) {
	if browserToken == "" {
		return nil, nil
	}
	rows, err := d.pool.Query(ctx,
		`UPDATE sso_sessions s
		    SET last_seen_at = now(), expires_at = now() + $2::interval
		   FROM users u
		  WHERE s.browser_hash = $1 AND s.expires_at > now()
		    AND u.id = s.user_id AND u.active
		 RETURNING `+prefixed("s.", sessionColumns),
		HashToken(browserToken), SessionTTL.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortSessions(out)
	return out, nil
}

// SessionBySID loads a live session by its public id.
func (d *DB) SessionBySID(ctx context.Context, sid string) (*Session, error) {
	return scanSession(d.pool.QueryRow(ctx,
		`SELECT `+sessionColumns+` FROM sso_sessions WHERE sid = $1 AND expires_at > now()`, sid))
}

// SetDefaultSession makes one of the browser's accounts its default.
func (d *DB) SetDefaultSession(ctx context.Context, browserToken string, ordinal int) error {
	tag, err := d.pool.Exec(ctx,
		`UPDATE sso_sessions SET is_default = (ordinal = $2)
		  WHERE browser_hash = $1
		    AND EXISTS (SELECT 1 FROM sso_sessions WHERE browser_hash = $1 AND ordinal = $2)`,
		HashToken(browserToken), ordinal)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// EndedSession is what signing an account out of a browser leaves to clean up
// at the sites.
type EndedSession struct {
	UserID    int64
	SID       string
	ClientIDs []string // the sites that held tokens from this session
}

// EndSession signs one account out of one browser: it deletes the session,
// revokes the refresh tokens issued under it, and promotes another account to
// default if this one was.
func (d *DB) EndSession(ctx context.Context, browserToken string, ordinal int) (*EndedSession, error) {
	return d.endWhere(ctx, `browser_hash = $1 AND ordinal = $2`, HashToken(browserToken), ordinal)
}

// SessionsSignedInTo returns the sids of the sessions in a browser that signed
// in to a client: those with a live refresh token issued to it.
func (d *DB) SessionsSignedInTo(ctx context.Context, browserToken, clientID string) ([]string, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT s.sid FROM sso_sessions s
		  WHERE s.browser_hash = $1
		    AND EXISTS (SELECT 1 FROM refresh_tokens r
		                 WHERE r.sid = s.sid AND r.client_id = $2 AND r.revoked_at IS NULL)
		  ORDER BY s.ordinal`, HashToken(browserToken), clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			return nil, err
		}
		out = append(out, sid)
	}
	return out, rows.Err()
}

// EndSessionBySID signs out the session with the given public id, wherever it
// is.
func (d *DB) EndSessionBySID(ctx context.Context, sid string) (*EndedSession, error) {
	return d.endWhere(ctx, `sid = $1`, sid)
}

func (d *DB) endWhere(ctx context.Context, where string, args ...any) (*EndedSession, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var e EndedSession
	var browser string
	var wasDefault bool
	if err := tx.QueryRow(ctx,
		`DELETE FROM sso_sessions WHERE `+where+` RETURNING user_id, sid, browser_hash, is_default`, args...).
		Scan(&e.UserID, &e.SID, &browser, &wasDefault); err != nil {
		return nil, norm(err)
	}
	if wasDefault {
		if _, err := tx.Exec(ctx,
			`UPDATE sso_sessions SET is_default = TRUE
			  WHERE browser_hash = $1
			    AND ordinal = (SELECT min(ordinal) FROM sso_sessions WHERE browser_hash = $1)`, browser); err != nil {
			return nil, err
		}
	}
	if e.ClientIDs, err = revokeForSID(ctx, tx, e.UserID, e.SID); err != nil {
		return nil, err
	}
	return &e, tx.Commit(ctx)
}

// EndBrowser signs every account out of one browser.
func (d *DB) EndBrowser(ctx context.Context, browserToken string) ([]EndedSession, error) {
	var ended []EndedSession
	for {
		sessions, err := d.pool.Query(ctx,
			`SELECT ordinal FROM sso_sessions WHERE browser_hash = $1 ORDER BY ordinal LIMIT 1`,
			HashToken(browserToken))
		if err != nil {
			return ended, err
		}
		var ordinal int
		found := sessions.Next()
		if found {
			err = sessions.Scan(&ordinal)
		}
		sessions.Close()
		if err != nil {
			return ended, err
		}
		if !found {
			return ended, nil
		}
		e, err := d.EndSession(ctx, browserToken, ordinal)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return ended, err
		}
		if e != nil {
			ended = append(ended, *e)
		}
	}
}

// EndAllSessions signs an account out of every browser and revokes every refresh
// token it holds, returning the clients that held one.
//
// Both halves together, or "sign out everywhere" leaves a refresh token that
// silently mints new access tokens afterwards — which is exactly what the person
// asked to stop.
func (d *DB) EndAllSessions(ctx context.Context, userID int64) ([]string, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Promote a replacement default in any browser that loses its default.
	if _, err := tx.Exec(ctx,
		`WITH gone AS (DELETE FROM sso_sessions WHERE user_id = $1 RETURNING browser_hash, is_default)
		 UPDATE sso_sessions s SET is_default = TRUE
		   FROM gone g
		  WHERE g.is_default AND s.browser_hash = g.browser_hash
		    AND s.ordinal = (SELECT min(ordinal) FROM sso_sessions x
		                      WHERE x.browser_hash = g.browser_hash AND x.user_id <> $1)`, userID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx,
		`UPDATE refresh_tokens SET revoked_at = now()
		  WHERE user_id = $1 AND revoked_at IS NULL
		 RETURNING client_id`, userID)
	if err != nil {
		return nil, err
	}
	ids, err := distinctClientIDs(rows)
	if err != nil {
		return nil, err
	}
	return ids, tx.Commit(ctx)
}

// revokeForSID revokes the refresh tokens issued under a session. Tokens
// recorded without a sid predate session tracking and are revoked too: there is
// no telling which browser they belong to.
func revokeForSID(ctx context.Context, tx pgx.Tx, userID int64, sid string) ([]string, error) {
	rows, err := tx.Query(ctx,
		`UPDATE refresh_tokens SET revoked_at = now()
		  WHERE user_id = $1 AND revoked_at IS NULL AND (sid = $2 OR sid IS NULL)
		 RETURNING client_id`, userID, sid)
	if err != nil {
		return nil, err
	}
	return distinctClientIDs(rows)
}

// distinctClientIDs drains rows of client_id, keeping each once.
func distinctClientIDs(rows pgx.Rows) ([]string, error) {
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

func sortSessions(s []Session) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].Ordinal < s[j-1].Ordinal; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// prefixed qualifies each column in a comma-separated list.
func prefixed(p, columns string) string {
	out := ""
	start := 0
	for i := 0; i <= len(columns); i++ {
		if i == len(columns) || columns[i] == ',' {
			col := columns[start:i]
			for len(col) > 0 && col[0] == ' ' {
				col = col[1:]
			}
			if out != "" {
				out += ", "
			}
			out += p + col
			start = i + 1
		}
	}
	return out
}
