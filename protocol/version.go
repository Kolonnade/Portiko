// Package protocol defines the wire contract shared by the accounts service and
// every relying party: the protocol version, how versions are negotiated, the
// discovery documents, and the claim and error names.
//
// Nothing in this package talks to a network or a database. It is the piece an
// independent implementation can depend on without inheriting our server.
package protocol

import (
	"fmt"
	"strconv"
	"strings"
)

// Name identifies the protocol in discovery documents.
const Name = "portiko"

// HeaderVersion carries the negotiated protocol version on every request and
// response, modelled on Connect-Protocol-Version.
const HeaderVersion = "Accounts-Protocol-Version"

// Version is a MAJOR.MINOR protocol version.
//
// The compatibility rule is HTTP-shaped and load-bearing:
//
//   - MAJOR changes are breaking. A new major is served at a new path prefix so
//     both can run at once during a migration.
//   - MINOR changes are additive only. A 1.0 client MUST work unchanged against
//     a 1.3 server, and a 1.3 client MUST work against a 1.0 server as long as
//     it treats everything added after 1.0 as optional.
type Version struct {
	Major int
	Minor int
}

// Supported versions of this build.
//
// VersionMin and VersionMax bracket what this library can speak. A relying party
// checks this range against the server's advertised range at startup, so an
// incompatible pair fails to boot rather than failing at a user's first sign-in.
var (
	V1_0       = Version{1, 0}
	VersionMin = V1_0
	VersionMax = V1_0
)

// ParseVersion parses a "MAJOR.MINOR" string. Both components are required:
// accepting a bare "1" would make the negotiation rules ambiguous.
func ParseVersion(s string) (Version, error) {
	major, minor, ok := strings.Cut(strings.TrimSpace(s), ".")
	if !ok {
		return Version{}, fmt.Errorf("protocol: version %q is not MAJOR.MINOR", s)
	}
	maj, err := strconv.Atoi(major)
	if err != nil || maj < 0 {
		return Version{}, fmt.Errorf("protocol: version %q has an invalid major", s)
	}
	min, err := strconv.Atoi(minor)
	if err != nil || min < 0 {
		return Version{}, fmt.Errorf("protocol: version %q has an invalid minor", s)
	}
	return Version{Major: maj, Minor: min}, nil
}

// String renders the version for a header or a discovery document.
func (v Version) String() string { return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) }

// Compare orders two versions: -1 if v < o, 0 if equal, +1 if v > o.
func (v Version) Compare(o Version) int {
	switch {
	case v.Major != o.Major:
		if v.Major < o.Major {
			return -1
		}
		return 1
	case v.Minor != o.Minor:
		if v.Minor < o.Minor {
			return -1
		}
		return 1
	default:
		return 0
	}
}

// PathPrefix returns the URL prefix carrying this major version, e.g. "/accounts/v1".
// Only the major appears: minors are additive and share a path tree.
func (v Version) PathPrefix() string { return "/accounts/v" + strconv.Itoa(v.Major) }

// ErrUnsupportedVersion is returned when no common version exists. It is
// reported to clients as a 400 with the server's supported list — never a 404,
// which would look like a routing problem and send the reader somewhere useless.
type ErrUnsupportedVersion struct {
	Requested Version
	Supported []Version
}

func (e *ErrUnsupportedVersion) Error() string {
	parts := make([]string, len(e.Supported))
	for i, v := range e.Supported {
		parts[i] = v.String()
	}
	return fmt.Sprintf("protocol: version %s is not supported (supported: %s)",
		e.Requested, strings.Join(parts, ", "))
}

// Negotiate picks the version a server should answer with, given what a client
// asked for and what the server can serve.
//
// The rules, in order:
//
//  1. The major must match one the server serves; there is no cross-major
//     fallback, because a major change is breaking by definition.
//  2. Within that major, answer at min(client minor, server's highest minor).
//     A client asking for more than we have gets our best, and additive-only
//     minors guarantee it can cope. A client asking for less gets exactly what
//     it asked for.
func Negotiate(requested Version, supported []Version) (Version, error) {
	best := Version{Major: -1}
	for _, s := range supported {
		if s.Major != requested.Major {
			continue
		}
		if best.Major < 0 || s.Compare(best) > 0 {
			best = s
		}
	}
	if best.Major < 0 {
		return Version{}, &ErrUnsupportedVersion{Requested: requested, Supported: supported}
	}
	if requested.Compare(best) < 0 {
		return requested, nil
	}
	return best, nil
}
