// Package config loads runtime configuration from the environment.
//
// Nothing here has a product name, a domain, or a brand baked in. That is a
// requirement, not a style preference: the same binary must serve a second,
// entirely separate deployment for a different domain and a different set of
// apps, with a different database and no shared state.
package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// Config is the full runtime configuration.
type Config struct {
	Port int

	// Issuer is this deployment's public base URL, e.g.
	// https://accounts.terriblename.com. It is what appears in `iss` and what
	// every discovery URL is built from, so it must be exact — no trailing
	// slash, correct scheme.
	Issuer string

	DatabaseURL string

	// ServiceName appears in the sign-in UI and as the WebAuthn RP display name.
	ServiceName string

	// WebAuthnRPID is the Relying Party ID: a bare domain, no scheme, no port.
	//
	// This is the most consequential value in the file. A passkey is bound to
	// it at creation and can never be used against a different one, so changing
	// it means every enrolled user re-enrolls.
	WebAuthnRPID string

	// WebAuthnRPOrigins are exact-matched against clientDataJSON.origin.
	//
	// Browsers send the page origin (https://accounts.example.com). Native
	// Apple clients using Associated Domains send https://<rp-id>. When both
	// client types exist, BOTH forms must be listed.
	WebAuthnRPOrigins []string

	// SMTP, not a vendor SDK, so a self-hosted deployment can point at any
	// provider.
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	EmailFrom    string

	// TemplateDir optionally overrides the built-in sign-in page templates, so a
	// second deployment can be rebranded without a fork.
	TemplateDir string

	// BootstrapCode enrolls the very first account. A fresh deployment has no
	// users and no passkeys, so without a deliberate bootstrap path there is no
	// way in at all.
	BootstrapCode string

	// DevInsecure allows http:// origins and drops Secure cookie flags. Local
	// development only; Load refuses it when Issuer is https.
	DevInsecure bool

	// CryptoKey encrypts the authorization codes zitadel/oidc hands out, and the
	// signing keys at rest. It must be the same on every replica and stable across
	// restarts, or a code issued a moment before a restart stops redeeming — and
	// the signing keys stop decrypting. 32 bytes, as hex or base64.
	CryptoKey [32]byte

	// TrustedProxies are the addresses whose X-Forwarded-For header is believed.
	//
	// Empty by default, and that default is the safe one: with nothing listed,
	// every request's address is its RemoteAddr. Trusting the header from anyone
	// means a client can claim any address it likes and a per-IP rate limit
	// becomes decoration. Behind a reverse proxy on the same host, this is
	// "127.0.0.1,::1"; list a bare address or a CIDR.
	TrustedProxies []netip.Prefix
}

const defaultPort = 8090

// Load reads and validates configuration, reporting every problem it finds
// rather than only the first — a half-configured service is otherwise a series
// of restarts.
func Load() (*Config, error) {
	// A .env file is a development convenience; production sets the
	// environment through systemd. A missing file is not an error, and values
	// already in the environment win, so an explicit export always beats the
	// file.
	_ = godotenv.Load()

	c := &Config{
		Port:          defaultPort,
		Issuer:        strings.TrimSuffix(os.Getenv("ISSUER"), "/"),
		DatabaseURL:   os.Getenv("DATABASE_URL"),
		ServiceName:   envOr("SERVICE_NAME", "Accounts"),
		WebAuthnRPID:  os.Getenv("WEBAUTHN_RP_ID"),
		SMTPHost:      os.Getenv("SMTP_HOST"),
		SMTPUsername:  os.Getenv("SMTP_USERNAME"),
		SMTPPassword:  os.Getenv("SMTP_PASSWORD"),
		EmailFrom:     os.Getenv("EMAIL_FROM"),
		TemplateDir:   os.Getenv("TEMPLATE_DIR"),
		BootstrapCode: os.Getenv("BOOTSTRAP_CODE"),
		DevInsecure:   os.Getenv("DEV_INSECURE") == "true",
	}

	var problems []string

	if v := os.Getenv("PORT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			problems = append(problems, "PORT must be an integer")
		} else {
			c.Port = n
		}
	}
	c.SMTPPort = 587
	if v := os.Getenv("SMTP_PORT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			problems = append(problems, "SMTP_PORT must be an integer")
		} else {
			c.SMTPPort = n
		}
	}

	for _, o := range strings.Split(os.Getenv("WEBAUTHN_RP_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			c.WebAuthnRPOrigins = append(c.WebAuthnRPOrigins, o)
		}
	}

	if c.Issuer == "" {
		problems = append(problems, "ISSUER is required (e.g. https://accounts.example.com)")
	}
	if c.DatabaseURL == "" {
		problems = append(problems, "DATABASE_URL is required")
	}
	if c.WebAuthnRPID == "" {
		problems = append(problems, "WEBAUTHN_RP_ID is required")
	}
	if strings.Contains(c.WebAuthnRPID, "://") || strings.Contains(c.WebAuthnRPID, ":") {
		problems = append(problems, "WEBAUTHN_RP_ID must be a bare domain: no scheme, no port")
	}
	if len(c.WebAuthnRPOrigins) == 0 {
		problems = append(problems, "WEBAUTHN_RP_ORIGINS is required (comma-separated)")
	}
	if c.DevInsecure && strings.HasPrefix(c.Issuer, "https://") {
		problems = append(problems, "DEV_INSECURE must not be set for an https ISSUER")
	}

	for _, p := range strings.Split(os.Getenv("TRUSTED_PROXIES"), ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		prefix, err := parsePrefix(p)
		if err != nil {
			problems = append(problems, fmt.Sprintf("TRUSTED_PROXIES: %q is not an IP address or CIDR", p))
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, prefix)
	}

	if key, err := decodeKey(os.Getenv("CRYPTO_KEY")); err != nil {
		problems = append(problems, "CRYPTO_KEY "+err.Error()+" (generate one with: openssl rand -hex 32)")
	} else {
		c.CryptoKey = key
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("config: %s", strings.Join(problems, "; "))
	}
	return c, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// parsePrefix accepts either a CIDR or a bare address, which becomes a prefix
// covering only itself.
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// decodeKey reads a 32-byte key written as hex or base64.
func decodeKey(s string) ([32]byte, error) {
	var key [32]byte
	s = strings.TrimSpace(s)
	if s == "" {
		return key, fmt.Errorf("is required")
	}
	var raw []byte
	if b, err := hex.DecodeString(s); err == nil {
		raw = b
	} else if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		raw = b
	} else if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		raw = b
	} else {
		return key, fmt.Errorf("must be hex or base64")
	}
	if len(raw) != 32 {
		return key, fmt.Errorf("must be exactly 32 bytes, got %d", len(raw))
	}
	copy(key[:], raw)
	return key, nil
}
