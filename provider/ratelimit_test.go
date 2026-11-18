package provider

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/Kolonnade/Portiko/internal/config"
)

// A test deployment's e2e suite runs from one machine several times an hour and
// ran out of loginStarts; RATE_LIMIT_EXEMPT lets it through while every other
// caller is still limited.
func TestRateLimitExemptAddressIsNotLimited(t *testing.T) {
	cfg := &config.Config{
		TrustedProxies:  []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		RateLimitExempt: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	}
	// perAddress is set and the limiter has no database: if an exempt request
	// reached the per-address layer it would panic, so passing proves it skips
	// both layers.
	lim := limit{perAddress: 1, perIP: 2, window: time.Hour}
	l, err := newLimiter(nil, cfg, map[string]limit{"login.start": lim})
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	h := l.wrap("login.start", lim, emailFromQuery, ok)

	call := func(remote, forwarded string) int {
		r := httptest.NewRequest("GET", "/accounts/v1/login/start?email=a@example.test", nil)
		r.RemoteAddr = remote
		if forwarded != "" {
			r.Header.Set("X-Forwarded-For", forwarded)
		}
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code
	}

	for i := range 10 {
		if code := call("198.51.100.7:4000", ""); code != http.StatusOK {
			t.Fatalf("exempt address, request %d: got %d", i+1, code)
		}
		// Through the trusted proxy, the forwarded address is the one checked.
		if code := call("127.0.0.1:4000", "198.51.100.8"); code != http.StatusOK {
			t.Fatalf("exempt address behind the proxy, request %d: got %d", i+1, code)
		}
	}
}

func TestRateLimitNonExemptAddressIsStillLimited(t *testing.T) {
	cfg := &config.Config{
		TrustedProxies:  []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		RateLimitExempt: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	}
	lim := limit{perIP: 2, window: time.Hour}
	l, err := newLimiter(nil, cfg, map[string]limit{"login.finish": lim})
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	h := l.wrap("login.finish", lim, nil, ok)

	for _, c := range []struct{ name, remote, forwarded string }{
		{"outside the exempt range", "203.0.113.9:4000", ""},
		// A client cannot claim an exempt address unless a trusted proxy says so.
		{"forged header from an untrusted connection", "203.0.113.10:4000", "198.51.100.7"},
		// The proxy itself is not exempt just because it relays exempt traffic.
		{"behind the proxy, not exempt", "127.0.0.1:4000", "203.0.113.11"},
	} {
		var codes []int
		for range 3 {
			r := httptest.NewRequest("POST", "/accounts/v1/login/finish", nil)
			r.RemoteAddr = c.remote
			if c.forwarded != "" {
				r.Header.Set("X-Forwarded-For", c.forwarded)
			}
			w := httptest.NewRecorder()
			h(w, r)
			codes = append(codes, w.Code)
		}
		if codes[0] != http.StatusOK || codes[1] != http.StatusOK || codes[2] != http.StatusTooManyRequests {
			t.Errorf("%s: got %v, want [200 200 429]", c.name, codes)
		}
	}
}
