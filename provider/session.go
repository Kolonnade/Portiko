package provider

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Kolonnade/Portiko/internal/store"
)

// SSOCookieName is the provider's own cookie. Its value names a browser; the
// accounts signed in on that browser are rows keyed by the value's hash.
const SSOCookieName = "accounts_sso"

// SetSSOCookie writes the browser cookie.
//
// SameSite=Lax is what makes single sign-on work: the cookie must be readable
// when the browser arrives on a top-level redirect from a different site. Strict
// would suppress it on exactly that navigation. Lax still withholds it from
// cross-site POSTs, which is the case that matters for CSRF.
func SetSSOCookie(w http.ResponseWriter, token string, expires time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: SSOCookieName, Value: token, Path: "/", Expires: expires,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

// ClearSSOCookie expires the browser cookie.
func ClearSSOCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: SSOCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

func browserToken(r *http.Request) string {
	if ck, err := r.Cookie(SSOCookieName); err == nil {
		return ck.Value
	}
	return ""
}

// account is one signed-in account in this browser.
type account struct {
	store.Session
	User *store.User
}

// accounts resolves every account signed in on the requesting browser, in
// number order.
func (h *Auth) accounts(r *http.Request) []account {
	sessions, err := h.db.Sessions(r.Context(), browserToken(r))
	if err != nil || len(sessions) == 0 {
		return nil
	}
	out := make([]account, 0, len(sessions))
	for _, s := range sessions {
		u, err := h.db.ByID(r.Context(), s.UserID)
		if err != nil || !u.Active {
			continue
		}
		out = append(out, account{Session: s, User: u})
	}
	return out
}

// findAccount returns the account with number n, or nil. A missing number is
// never replaced with another account: the caller shows the chooser instead.
func findAccount(list []account, n int) *account {
	for i := range list {
		if list[i].Ordinal == n {
			return &list[i]
		}
	}
	return nil
}

func defaultAccount(list []account) *account {
	for i := range list {
		if list[i].IsDefault {
			return &list[i]
		}
	}
	if len(list) > 0 {
		return &list[0]
	}
	return nil
}

// selectAccount resolves an explicit account number, or the default when raw is
// empty. ok is false when a number was given that this browser does not hold.
func selectAccount(list []account, raw string) (*account, bool) {
	if raw == "" {
		a := defaultAccount(list)
		return a, a != nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return nil, false
	}
	a := findAccount(list, n)
	return a, a != nil
}

// clientIP resolves the address a request came from.
//
// X-Forwarded-For is believed only when the connection itself comes from a
// configured trusted proxy. The header is client-supplied: trusting it
// unconditionally lets anyone claim any address, which turns a per-IP rate limit
// into decoration and fills the audit trail with addresses of the attacker's
// choosing. With nothing configured — the default — only RemoteAddr is used.
//
// The walk is right to left. A proxy APPENDS the address it saw, so the rightmost
// entry is the one added by the proxy closest to this service and the only one
// not under the client's control. Entries that are themselves trusted proxies are
// skipped, so a chain of two or three is handled; if every entry is a trusted
// proxy, the leftmost is as close to the client as this deployment can get.
func clientIP(trusted []netip.Prefix, r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr // A test server, or a unix socket: use it as given.
	}
	if len(trusted) == 0 || !trustedAddr(trusted, host) {
		return host
	}
	forwarded := r.Header.Values("X-Forwarded-For")
	var hops []string
	for _, h := range forwarded {
		for _, part := range strings.Split(h, ",") {
			if part = strings.TrimSpace(part); part != "" {
				hops = append(hops, part)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if _, err := netip.ParseAddr(hops[i]); err != nil {
			// An unparseable hop means the header cannot be reasoned about at all;
			// fall back to the connection, which cannot be forged.
			return host
		}
		if !trustedAddr(trusted, hops[i]) {
			return hops[i]
		}
	}
	if len(hops) > 0 {
		return hops[0]
	}
	return host
}

func trustedAddr(trusted []netip.Prefix, host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap() // So an IPv4-mapped IPv6 address matches an IPv4 prefix.
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
