// Package localpath decides whether a return address is a path on this site.
//
// Both the provider's sign-in page and the rp package redirect to a
// caller-supplied return_to, so both use this one check. A looser check in
// either is an open redirect from a trusted domain.
package localpath

import (
	"net/url"
	"strings"
)

// Is reports whether p is a same-origin path: it starts with exactly one "/",
// contains no backslash or control character, and parses with no scheme and no
// host.
//
// Each refusal is a way a browser reads a "path" as another site. "//host" is
// protocol-relative. Browsers treat "\" as "/" in http(s) URLs, so "/\host" is
// "//host". They strip tab, CR and LF from URLs, so "/\t/host" is "//host" too.
func Is(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsRune(p, '\\') {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	u, err := url.Parse(p)
	return err == nil && u.Scheme == "" && u.Host == "" && u.User == nil
}

// Or returns p when it is a same-origin path, and fallback otherwise.
func Or(p, fallback string) string {
	if Is(p) {
		return p
	}
	return fallback
}
