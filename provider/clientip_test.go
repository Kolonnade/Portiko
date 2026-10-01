package provider

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// X-Forwarded-For is written by the client until a proxy overwrites or appends to
// it, so believing it from anyone lets a caller claim any address — which makes
// every per-IP limit decoration and fills the audit trail with addresses of the
// attacker's choosing. AccountsWeb #0012, and F13 behind it.
func TestClientIPTrustsForwardedHeaderOnlyFromAProxy(t *testing.T) {
	for _, c := range []struct {
		name      string
		trusted   string
		remote    string
		forwarded string
		want      string
	}{
		{
			name:      "nothing configured, so the header is ignored",
			remote:    "203.0.113.9:4000",
			forwarded: "1.2.3.4",
			want:      "203.0.113.9",
		},
		{
			name:    "no header at all",
			trusted: "127.0.0.1",
			remote:  "127.0.0.1:4000",
			want:    "127.0.0.1",
		},
		{
			name:      "one proxy on the same host",
			trusted:   "127.0.0.1",
			remote:    "127.0.0.1:4000",
			forwarded: "1.2.3.4",
			want:      "1.2.3.4",
		},
		{
			// The proxy appends what it saw, so the rightmost entry is the one the
			// client could not write. A client that sends its own X-Forwarded-For
			// must not be able to choose the answer.
			name:      "the client tried to forge an earlier hop",
			trusted:   "127.0.0.1",
			remote:    "127.0.0.1:4000",
			forwarded: "9.9.9.9, 1.2.3.4",
			want:      "1.2.3.4",
		},
		{
			name:      "two proxies in front, the inner one trusted",
			trusted:   "127.0.0.1,10.0.0.0/8",
			remote:    "127.0.0.1:4000",
			forwarded: "1.2.3.4, 10.1.2.3",
			want:      "1.2.3.4",
		},
		{
			name:      "the header arrives from somewhere untrusted",
			trusted:   "127.0.0.1",
			remote:    "198.51.100.7:4000",
			forwarded: "1.2.3.4",
			want:      "198.51.100.7",
		},
		{
			name:      "an unparseable hop falls back to the connection",
			trusted:   "127.0.0.1",
			remote:    "127.0.0.1:4000",
			forwarded: "not-an-ip",
			want:      "127.0.0.1",
		},
		{
			name:      "every hop is a trusted proxy, so the leftmost is as close as we get",
			trusted:   "127.0.0.1,10.0.0.0/8",
			remote:    "127.0.0.1:4000",
			forwarded: "10.0.0.1, 10.0.0.2",
			want:      "10.0.0.1",
		},
		{
			name:      "a CIDR covers the proxy",
			trusted:   "10.0.0.0/8",
			remote:    "10.4.5.6:4000",
			forwarded: "1.2.3.4",
			want:      "1.2.3.4",
		},
		{
			name:      "the header split over two header lines",
			trusted:   "127.0.0.1",
			remote:    "127.0.0.1:4000",
			forwarded: "9.9.9.9|1.2.3.4",
			want:      "1.2.3.4",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = c.remote
			for _, line := range strings.Split(c.forwarded, "|") {
				if line != "" {
					r.Header.Add("X-Forwarded-For", line)
				}
			}
			if got := clientIP(prefixes(t, c.trusted), r); got != c.want {
				t.Errorf("clientIP = %q, want %q", got, c.want)
			}
		})
	}
}

func prefixes(t *testing.T, list string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, p := range strings.Split(list, ",") {
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			addr, err := netip.ParseAddr(p)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, prefix)
	}
	return out
}
