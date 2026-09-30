package protocol

// Claim names carried by an access token. Standard JWT claims keep their
// standard names; ClaimProtocolVersion is the one extension, so a resource
// server knows which rules produced the token it is holding.
const (
	ClaimSubject         = "sub" // opaque, stable, "usr_…" — never an email
	ClaimIssuer          = "iss"
	ClaimAudience        = "aud" // exactly one app, always
	ClaimExpiry          = "exp"
	ClaimIssuedAt        = "iat"
	ClaimJWTID           = "jti"
	ClaimScope           = "scope"
	ClaimEmail           = "email"
	ClaimEmailVerified   = "email_verified"
	ClaimName            = "name"
	ClaimAvatar          = "avatar" // the emoji chosen on the accounts profile page; "profile" scope
	ClaimAuthMethods     = "amr"
	ClaimAuthTime        = "auth_time"
	ClaimNonce           = "nonce"
	ClaimProtocolVersion = "apv"
	ClaimSessionID       = "sid"    // the accounts SSO session a token was issued under
	ClaimEvents          = "events" // present only on security event tokens: logout, profile change
)

// EventBackchannelLogout is the event a back-channel logout token carries
// (OpenID Connect Back-Channel Logout 1.0).
const EventBackchannelLogout = "http://schemas.openid.net/event/backchannel-logout"

// ClaimUpdatedAt is the standard OIDC profile claim: when the profile last
// changed, in Unix seconds. Sites use it as the profile's version.
const ClaimUpdatedAt = "updated_at"

// EventTokenClaimsChange is the Shared Signals CAEP event a pushed security
// event token carries when claims about the subject — here, the profile — change.
const EventTokenClaimsChange = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"

// SigningAlg is the only signature algorithm this protocol permits.
//
// Pinning it is a security control, not a preference: a verifier that accepts
// "whatever the header says" accepts an attacker's choice of algorithm.
const SigningAlg = "ES256"

// Token type headers for the tokens Portiko signs itself. A verifier checks the
// header as well as the claims, so one kind of token can never be replayed as
// another (RFC 8725 §3.11).
const (
	TypeLogoutToken = "logout+jwt"   // OpenID Connect Back-Channel Logout
	TypeEventToken  = "secevent+jwt" // RFC 8417 Security Event Token
)

// SubjectPrefix prefixes every subject identifier. The value after it is
// opaque and carries no meaning — in particular it is not a row id and not
// derived from any identifier the user can change.
const SubjectPrefix = "usr_"

// OAuth and protocol error codes. The names match RFC 6749 where one exists so
// that a generic OAuth client reports something sensible.
const (
	ErrInvalidRequest      = "invalid_request"
	ErrInvalidClient       = "invalid_client"
	ErrInvalidGrant        = "invalid_grant"
	ErrUnauthorizedClient  = "unauthorized_client"
	ErrAccessDenied        = "access_denied"
	ErrServerError         = "server_error"
	ErrLoginRequired       = "login_required"
	ErrUnsupportedProtocol = "unsupported_protocol_version"
	ErrInvalidRedirectURI  = "invalid_redirect_uri"
	ErrConsentRequired     = "consent_required"
)

// Error is the JSON error body returned by every endpoint in this protocol.
type Error struct {
	Code        string   `json:"error"`
	Description string   `json:"error_description,omitempty"`
	Supported   []string `json:"versions_supported,omitempty"`
}

func (e *Error) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}
