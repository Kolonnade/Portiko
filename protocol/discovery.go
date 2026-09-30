package protocol

import "time"

// WellKnownPath is where a provider serves its Portiko configuration: the
// protocol version range, which OpenID Connect discovery has no field for.
const WellKnownPath = "/.well-known/portiko-configuration"

// LegacyWellKnownPath is the same document at the path the proof of concept
// used. A provider serves both until every relying party has moved.
const LegacyWellKnownPath = "/.well-known/eureka-accounts-configuration"

// DeprecatedVersion announces a version that will stop being served, with the
// date it goes away. Announcing the sunset in discovery is what lets an operator
// we do not control schedule their own upgrade.
type DeprecatedVersion struct {
	Version string    `json:"version"`
	Sunset  time.Time `json:"sunset"`
}

// Configuration is the vendor discovery document.
//
// It lists only what is built. An endpoint appears here in the same change that
// implements it and never before: a client written against discovery takes an
// advertised URL at its word, and a 404 behind it fails in ways that are hard
// to diagnose.
type Configuration struct {
	Protocol           string              `json:"protocol"`
	VersionsSupported  []string            `json:"versions_supported"`
	VersionMinimum     string              `json:"version_minimum"`
	VersionPreferred   string              `json:"version_preferred"`
	VersionsDeprecated []DeprecatedVersion `json:"versions_deprecated,omitempty"`
	Issuer             string              `json:"issuer"`
}

// Versions parses VersionsSupported, skipping anything unparseable so one bad
// entry from a newer server cannot make an older client refuse to start.
func (c Configuration) Versions() []Version {
	out := make([]Version, 0, len(c.VersionsSupported))
	for _, s := range c.VersionsSupported {
		if v, err := ParseVersion(s); err == nil {
			out = append(out, v)
		}
	}
	return out
}
