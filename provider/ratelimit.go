package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	golimiter "github.com/sethvargo/go-limiter"
	"github.com/sethvargo/go-limiter/memorystore"

	"github.com/Kolonnade/Portiko/internal/config"
	"github.com/Kolonnade/Portiko/internal/store"
	kitprotocol "github.com/Kolonnade/Portiko/protocol"
)

// ErrRateLimited is the error code a limited request is answered with.
//
// It is the same body for every cause and for every address: whether the budget
// that ran out was the caller's IP or the address it named, and whether that
// address has an account, are all invisible from the outside.
const ErrRateLimited = "rate_limited"

// Rate limits, per endpoint.
//
// The numbers are set for a deployment serving families, not a public sign-up
// funnel, and every one of them is a ceiling a real person will not reach: a
// household behind one address is the case that must not be locked out, so the
// per-IP limits are deliberately loose and the per-address limits — the ones that
// actually bound an attack on one account — are tight.
//
// Changing one of these is a product decision, not a tuning knob: too low locks a
// family out of their own accounts, and too high is the issue this fixes.
var (
	// codeRequests bounds asking for a one-time code for one address. Five an hour
	// is a person who did not receive the first one and tried again, several times.
	codeRequests = limit{perAddress: 5, perIP: 30, window: time.Hour}

	// codeVerifications bounds submitting a code. The real per-address limit on
	// this endpoint is the guess counter inside the store, which cannot be
	// bypassed by reaching the service another way; this is the per-IP backstop,
	// and it also catches bodies that are malformed and never reach the store.
	codeVerifications = limit{perIP: 60, window: time.Hour}

	// loginStarts bounds asking for assertion options. Cheap to serve, so the
	// limit is about flooding rather than guessing — nothing is guessable here.
	loginStarts = limit{perAddress: 60, perIP: 120, window: time.Hour}

	// loginFinishes bounds submitting an assertion. An assertion cannot be
	// guessed, so this bounds the signature verification work.
	loginFinishes = limit{perIP: 120, window: time.Hour}

	// tokenRequests bounds the OAuth token endpoint. It is deliberately the
	// loosest of the lot: the callers are relying parties, not browsers, and they
	// all arrive from the same handful of addresses — often one, when the sites run
	// on the same host. A limit tight enough to be interesting here would take a
	// site down under ordinary load, which is a worse outcome than the flood.
	tokenRequests = limit{perIP: 3600, window: time.Hour}
)

// limit is one endpoint's budget. A zero per-address or per-IP figure means that
// half is not applied.
type limit struct {
	perAddress int
	perIP      int
	window     time.Duration
}

// limiter applies the limits.
//
// Two layers, because they catch different things. The per-IP layer is in
// process: a flood from one address lands on one replica and is cheapest to stop
// there, and a limiter that needs a database round trip per request is itself a
// way to exhaust the database. The per-address layer is in Postgres, because it
// is the one that bounds what can be done to a single account and an attacker
// spreading requests across replicas would otherwise get each replica's budget.
type limiter struct {
	db      *store.DB
	cfg     *config.Config
	buckets map[string]golimiter.Store
}

// newLimiter builds the in-process stores, one per endpoint, so each endpoint's
// budget is its own.
func newLimiter(db *store.DB, cfg *config.Config, limits map[string]limit) (*limiter, error) {
	l := &limiter{db: db, cfg: cfg, buckets: map[string]golimiter.Store{}}
	for name, lim := range limits {
		if lim.perIP == 0 {
			continue
		}
		s, err := memorystore.New(&memorystore.Config{
			Tokens:   uint64(lim.perIP),
			Interval: lim.window,
			// Keep a bucket at least as long as its own window, or a key is purged
			// mid-window and the budget silently restarts.
			SweepMinTTL: 2 * lim.window,
		})
		if err != nil {
			return nil, fmt.Errorf("provider: rate limiter for %s: %w", name, err)
		}
		l.buckets[name] = s
	}
	return l, nil
}

// close releases the in-process stores.
func (l *limiter) close() {
	for _, s := range l.buckets {
		_ = s.Close(context.Background())
	}
}

// wrap applies one endpoint's limits to a handler.
//
// address, when set, pulls the address the request is about out of it — so the
// per-address budget can be charged before anything looks the address up, and
// long before it is known whether an account exists.
func (l *limiter) wrap(name string, lim limit, address func(*http.Request) string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(l.cfg.TrustedProxies, r)
		if s := l.buckets[name]; s != nil && ip != "" {
			_, _, reset, ok, err := s.Take(r.Context(), name+"|"+ip)
			if err != nil {
				slog.ErrorContext(r.Context(), "rate limiter failed", "endpoint", name, "err", err)
				writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
				return
			}
			if !ok {
				limited(w, r, name, "ip", time.Until(time.Unix(0, int64(reset))))
				return
			}
		}
		if lim.perAddress > 0 && address != nil {
			if email := store.NormalizeEmail(address(r)); email != "" {
				// Hashed, so the counter table does not become a list of the
				// addresses that have been asked about.
				d, err := l.db.Allow(r.Context(), "endpoint."+name, store.HashToken(email), lim.perAddress, lim.window)
				if err != nil {
					slog.ErrorContext(r.Context(), "rate limiter failed", "endpoint", name, "err", err)
					writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
					return
				}
				if !d.OK {
					limited(w, r, name, "address", d.RetryAfter)
					return
				}
			}
		}
		next(w, r)
	}
}

// limited writes the one response every refusal gets.
//
// Retry-After is in seconds and always at least one, so a client that honors it
// waits rather than retrying at once and making the flood worse. The log line
// names which budget ran out, because the response deliberately does not.
func limited(w http.ResponseWriter, r *http.Request, endpoint, which string, retryAfter time.Duration) {
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	slog.WarnContext(r.Context(), "rate limited", "endpoint", endpoint, "budget", which,
		"retry_after", retryAfter.Round(time.Second))
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Round(time.Second)/time.Second)))
	writeError(w, http.StatusTooManyRequests, &kitprotocol.Error{Code: ErrRateLimited})
}

// emailFromBody reads the address out of a JSON body without consuming it.
//
// The body is read, parsed and put back, because the handler behind this needs it
// too. It is already capped at 4 KiB by every one of those handlers; the same cap
// is applied here so that reading it cannot be made expensive.
func emailFromBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	blob, err := io.ReadAll(io.LimitReader(r.Body, 4<<10))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(blob))
	if err != nil {
		return ""
	}
	var body struct {
		Email string `json:"email"`
	}
	if json.Unmarshal(blob, &body) != nil {
		return ""
	}
	return body.Email
}

// emailFromQuery reads the address from the query string, for login/start.
func emailFromQuery(r *http.Request) string { return r.URL.Query().Get("email") }
