package provider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Kolonnade/Portiko/internal/config"
	"github.com/Kolonnade/Portiko/internal/keys"
	"github.com/Kolonnade/Portiko/internal/store"
	"github.com/Kolonnade/Portiko/profile"
	"github.com/Kolonnade/Portiko/protocol"
)

// AccessTokenTTL bounds how long a revoked account keeps working access at a
// site. With server-side refresh the renewal is invisible to the person.
const AccessTokenTTL = 15 * time.Minute

// IDTokenTTL is short because an ID token is consumed at sign-in and never
// presented to an API.
const IDTokenTTL = 5 * time.Minute

// storage is Portiko's op.Storage: every piece of protocol state zitadel/oidc
// needs, kept in PostgreSQL.
type storage struct {
	db       *store.DB
	ring     *keys.Ring
	cfg      *config.Config
	profiles profile.Source
	// ended is told when an OpenID end-session request signs an account out, so
	// the sites that held its tokens receive back-channel logout.
	ended func(ctx context.Context, subject, sid string, clientIDs []string)
}

var (
	_ op.Storage                       = (*storage)(nil)
	_ op.CanSetUserinfoFromRequest     = (*storage)(nil)
	_ op.CanGetPrivateClaimsFromRequest = (*storage)(nil)
	_ op.CanTerminateSessionFromRequest = (*storage)(nil)
)

// ---------------------------------------------------------------- clients

func (s *storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	c, err := s.db.ClientByID(ctx, clientID)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithParent(err)
	}
	return &client{Client: c, issuer: s.cfg.Issuer, dev: s.cfg.DevInsecure}, nil
}

func (s *storage) AuthorizeClientIDSecret(ctx context.Context, clientID, secret string) error {
	c, err := s.db.ClientByID(ctx, clientID)
	if err != nil {
		return oidc.ErrInvalidClient().WithParent(err)
	}
	// A public client has no secret to present; it authenticates with PKCE.
	if c.SecretHash == "" || !store.SecretMatches(secret, c.SecretHash) {
		return oidc.ErrInvalidClient().WithDescription("client authentication failed")
	}
	return nil
}

// ---------------------------------------------------------- auth requests

func (s *storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, hintSubject string) (op.AuthRequest, error) {
	c, err := s.db.ClientByID(ctx, req.ClientID)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithParent(err)
	}
	// PKCE for every client, confidential ones included: a client secret does
	// not protect a code stolen from the redirect itself.
	if req.CodeChallenge == "" || req.CodeChallengeMethod != oidc.CodeChallengeMethodS256 {
		return nil, oidc.ErrInvalidRequest().WithDescription("PKCE with code_challenge_method=S256 is required")
	}
	// A client is granted only what it was registered for. Standard scopes get
	// no pass: a client that was not allowed "email" does not receive it.
	scopes := make([]string, 0, len(req.Scopes))
	for _, sc := range req.Scopes {
		if c.AllowsScope(sc) && !slices.Contains(scopes, sc) {
			scopes = append(scopes, sc)
		}
	}
	if !slices.Contains(scopes, oidc.ScopeOpenID) {
		return nil, oidc.ErrInvalidScope().WithDescription("openid is required, and must be allowed for this client")
	}
	var maxAge *int
	if req.MaxAge != nil {
		v := int(*req.MaxAge)
		maxAge = &v
	}
	created, err := s.db.CreateAuthRequest(ctx, store.AuthRequest{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		ResponseType:        string(req.ResponseType),
		ResponseMode:        string(req.ResponseMode),
		Scopes:              scopes,
		State:               req.State,
		Nonce:               req.Nonce,
		Prompt:              []string(req.Prompt),
		MaxAge:              maxAge,
		LoginHint:           req.LoginHint,
		HintSubject:         hintSubject,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: string(req.CodeChallengeMethod),
	})
	if err != nil {
		return nil, err
	}
	return &authRequest{created}, nil
}

func (s *storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	a, err := s.db.AuthRequestByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return &authRequest{a}, nil
}

func (s *storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	a, err := s.db.ConsumeAuthCode(ctx, code)
	if err != nil {
		return nil, oidc.ErrInvalidGrant().WithDescription("code is invalid, expired or already used").WithParent(err)
	}
	return &authRequest{a}, nil
}

func (s *storage) SaveAuthCode(ctx context.Context, id, code string) error {
	return s.db.SaveAuthCode(ctx, id, code)
}

func (s *storage) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.db.DeleteAuthRequest(ctx, id)
}

// ----------------------------------------------------------------- tokens

func (s *storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	return accessTokenID(request.GetScopes()), time.Now().Add(AccessTokenTTL), nil
}

// emailGrantSuffix marks an access token whose grant included the email scope.
const emailGrantSuffix = ".email"

// accessTokenID mints an access token's jti. It records whether email was
// granted, because the userinfo endpoint is handed only the jti and the subject
// of the (signed, verified) token, not its scopes, and must not return the
// address to a site that was not granted it.
func accessTokenID(scopes []string) string {
	id := uuid.NewString()
	if slices.Contains(scopes, oidc.ScopeEmail) {
		id += emailGrantSuffix
	}
	return id
}

func (s *storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, current string) (string, string, time.Time, error) {
	id, exp := accessTokenID(request.GetScopes()), time.Now().Add(AccessTokenTTL)
	switch r := request.(type) {
	case *authRequest:
		if r.UserID == nil {
			return "", "", time.Time{}, oidc.ErrInvalidGrant().WithDescription("authorization request was not completed")
		}
		token, err := s.db.CreateRefreshToken(ctx, store.RefreshToken{
			ClientID: r.ClientID, UserID: *r.UserID, Scopes: r.Scopes,
			SID: r.SID, AuthTime: r.AuthTime, AMR: r.AMR,
		})
		return id, token, exp, err
	case *refreshTokenRequest:
		token, err := s.db.RotateRefreshToken(ctx, current, store.RefreshToken{
			ClientID: r.ClientID, UserID: r.UserID, Scopes: r.GetScopes(),
			SID: r.SID, AuthTime: r.AuthTime, AMR: r.AMR,
		})
		return id, token, exp, err
	default:
		return "", "", time.Time{}, fmt.Errorf("provider: unsupported token request %T", request)
	}
}

func (s *storage) TokenRequestByRefreshToken(ctx context.Context, token string) (op.RefreshTokenRequest, error) {
	rt, err := s.db.RefreshTokenByToken(ctx, token)
	if err != nil {
		return nil, oidc.ErrInvalidGrant().WithDescription("refresh token is invalid or revoked").WithParent(err)
	}
	// A refresh token is offline access by definition. Tokens issued before
	// Portiko recorded the scope explicitly, and a relying party that asks for it
	// again on refresh must not be refused over the difference.
	if !slices.Contains(rt.Scopes, oidc.ScopeOfflineAccess) {
		rt.Scopes = append(rt.Scopes, oidc.ScopeOfflineAccess)
	}
	return &refreshTokenRequest{RefreshToken: rt, scopes: rt.Scopes}, nil
}

func (s *storage) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (string, string, error) {
	rt, err := s.db.RefreshTokenByToken(ctx, token)
	if err != nil || rt.ClientID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return rt.Subject, token, nil
}

func (s *storage) RevokeToken(ctx context.Context, tokenOrID, _ string, clientID string) *oidc.Error {
	if err := s.db.RevokeRefreshFamily(ctx, tokenOrID, clientID); err != nil {
		slog.ErrorContext(ctx, "revoking refresh token", "err", err)
		return oidc.ErrServerError()
	}
	return nil
}

func (s *storage) TerminateSession(ctx context.Context, subject, clientID string) error {
	u, err := s.db.BySubject(ctx, subject)
	if err != nil {
		return nil
	}
	return s.db.RevokeRefreshForClient(ctx, u.ID, clientID)
}

// TerminateSessionFromRequest handles OpenID Connect RP-initiated logout. With
// an ID token naming a session, that account's session ends in the browser it
// came from, and every site that held tokens from it is told.
func (s *storage) TerminateSessionFromRequest(ctx context.Context, req *op.EndSessionRequest) (string, error) {
	if req.IDTokenHintClaims != nil && req.IDTokenHintClaims.SessionID != "" {
		ended, err := s.db.EndSessionBySID(ctx, req.IDTokenHintClaims.SessionID)
		switch {
		case err == nil:
			if s.ended != nil {
				s.ended(ctx, req.IDTokenHintClaims.Subject, ended.SID, ended.ClientIDs)
			}
		case !errors.Is(err, store.ErrNotFound):
			return "", err
		}
	} else if req.UserID != "" && req.ClientID != "" {
		if err := s.TerminateSession(ctx, req.UserID, req.ClientID); err != nil {
			return "", err
		}
	} else if req.IDTokenHintClaims == nil && req.ClientID != "" {
		if err := s.endBrowserSessionsFor(ctx, req.ClientID); err != nil {
			return "", err
		}
	}
	return req.RedirectURI, nil
}

// endBrowserSessionsFor handles an end-session request with no id_token_hint:
// a site that lost its own session (a restart, an expired cookie) sends the
// browser here to sign out. The site cannot say which account it meant, so the
// sessions that end are the ones in this browser that signed in to that site,
// found by the refresh tokens issued to it under each session. Other accounts
// in the browser stay signed in, and nothing ends if none signed in to it.
//
// Anyone can send a browser here, as with any RP-initiated logout without a
// hint. The worst it does is sign an account out of the sites it is signed in
// to through this one.
func (s *storage) endBrowserSessionsFor(ctx context.Context, clientID string) error {
	token := browserTokenFrom(ctx)
	if token == "" {
		return nil
	}
	sids, err := s.db.SessionsSignedInTo(ctx, token, clientID)
	if err != nil {
		return err
	}
	for _, sid := range sids {
		ended, err := s.db.EndSessionBySID(ctx, sid)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if s.ended != nil {
			if u, err := s.db.ByID(ctx, ended.UserID); err == nil {
				s.ended(ctx, u.Subject, ended.SID, ended.ClientIDs)
			}
		}
	}
	return nil
}

type browserTokenKey struct{}

// withBrowserToken hands the end-session endpoint the browser's SSO cookie,
// which zitadel/oidc does not pass to storage.
func withBrowserToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if t := browserToken(r); t != "" {
			r = r.WithContext(context.WithValue(r.Context(), browserTokenKey{}, t))
		}
		next.ServeHTTP(w, r)
	})
}

func browserTokenFrom(ctx context.Context) string {
	t, _ := ctx.Value(browserTokenKey{}).(string)
	return t
}

// ----------------------------------------------------------------- claims

func (s *storage) SetUserinfoFromScopes(ctx context.Context, info *oidc.UserInfo, subject, _ string, scopes []string) error {
	return s.fillUserinfo(ctx, info, subject, scopes)
}

// SetUserinfoFromRequest fills the ID token. Besides the session, it carries
// the primary email when email was granted: zitadel/oidc drops the userinfo
// scopes from an ID token issued alongside an access token, and a site reading
// the address from the ID token must see the current primary at each sign-in.
// Profile claims stay out of the ID token, as before.
func (s *storage) SetUserinfoFromRequest(ctx context.Context, info *oidc.UserInfo, request op.IDTokenRequest, _ []string) error {
	if sid := sidOf(request); sid != "" {
		info.AppendClaims(protocol.ClaimSessionID, sid)
	}
	if slices.Contains(request.GetScopes(), oidc.ScopeEmail) {
		claims, err := s.claimsFor(ctx, request.GetSubject(), []string{oidc.ScopeEmail})
		if err != nil {
			return err
		}
		if email, ok := claims[protocol.ClaimEmail].(string); ok {
			info.Email = email
			info.EmailVerified = oidc.Bool(true)
		}
	}
	return nil
}

// SetUserinfoFromToken fills the userinfo response. Profile claims are always
// included, as they always have been; email only when the token's grant
// included it (see accessTokenID). The address is read now, so it is the
// current primary.
func (s *storage) SetUserinfoFromToken(ctx context.Context, info *oidc.UserInfo, tokenID, subject, _ string) error {
	scopes := []string{oidc.ScopeOpenID, oidc.ScopeProfile}
	if strings.HasSuffix(tokenID, emailGrantSuffix) {
		scopes = append(scopes, oidc.ScopeEmail)
	}
	return s.fillUserinfo(ctx, info, subject, scopes)
}

func (s *storage) SetIntrospectionFromToken(ctx context.Context, resp *oidc.IntrospectionResponse, _, subject, clientID string) error {
	resp.Active = true
	resp.Subject = subject
	resp.ClientID = clientID
	return nil
}

func (s *storage) GetPrivateClaimsFromScopes(ctx context.Context, subject, _ string, scopes []string) (map[string]any, error) {
	return s.claimsFor(ctx, subject, scopes)
}

// GetPrivateClaimsFromRequest adds to every access token what a site needs from
// it: the session it came from, when and how the person authenticated, the
// protocol version, and the presentation and email the granted scopes allow.
func (s *storage) GetPrivateClaimsFromRequest(ctx context.Context, request op.TokenRequest, _ []string) (map[string]any, error) {
	claims, err := s.claimsFor(ctx, request.GetSubject(), request.GetScopes())
	if err != nil {
		return nil, err
	}
	claims[protocol.ClaimProtocolVersion] = Preferred.String()
	if sid := sidOf(request); sid != "" {
		claims[protocol.ClaimSessionID] = sid
	}
	if at, amr := authOf(request); !at.IsZero() {
		claims[protocol.ClaimAuthTime] = at.Unix()
		if len(amr) > 0 {
			claims[protocol.ClaimAuthMethods] = amr
		}
	}
	return claims, nil
}

func (s *storage) claimsFor(ctx context.Context, subject string, scopes []string) (map[string]any, error) {
	claims := map[string]any{}
	if slices.Contains(scopes, oidc.ScopeProfile) {
		p, err := s.profiles.Presentation(ctx, subject)
		if err != nil {
			return nil, err
		}
		if p.Name != "" {
			claims[protocol.ClaimName] = p.Name
		}
		if p.Avatar != "" {
			claims[protocol.ClaimAvatar] = p.Avatar
		}
		if p.UpdatedAt != 0 {
			claims[protocol.ClaimUpdatedAt] = p.UpdatedAt
		}
		for k, v := range p.Extra {
			if _, taken := claims[k]; !taken {
				claims[k] = v
			}
		}
	}
	if slices.Contains(scopes, oidc.ScopeEmail) {
		if u, err := s.db.BySubject(ctx, subject); err == nil {
			if email, err := s.db.PrimaryEmail(ctx, u.ID); err == nil && email != "" {
				claims[protocol.ClaimEmail] = email
				claims[protocol.ClaimEmailVerified] = true
			}
		}
	}
	return claims, nil
}

func (s *storage) fillUserinfo(ctx context.Context, info *oidc.UserInfo, subject string, scopes []string) error {
	info.Subject = subject
	claims, err := s.claimsFor(ctx, subject, scopes)
	if err != nil {
		return err
	}
	for k, v := range claims {
		switch k {
		case protocol.ClaimName:
			info.Name, _ = v.(string)
		case protocol.ClaimEmail:
			info.Email, _ = v.(string)
		case protocol.ClaimEmailVerified:
			info.EmailVerified = oidc.Bool(true)
		case protocol.ClaimUpdatedAt:
			if n, ok := v.(int64); ok {
				info.UpdatedAt = oidc.FromTime(time.Unix(n, 0))
			}
		default:
			info.AppendClaims(k, v)
		}
	}
	return nil
}

// ------------------------------------------------------------------- keys

func (s *storage) SigningKey(context.Context) (op.SigningKey, error) { return s.ring.SigningKey(), nil }

func (s *storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.ES256}, nil
}

func (s *storage) KeySet(context.Context) ([]op.Key, error) { return s.ring.PublicKeys(), nil }

var errJWTProfileUnsupported = errors.New("provider: JWT profile grants are not supported")

func (s *storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errJWTProfileUnsupported
}

func (s *storage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errJWTProfileUnsupported
}

func (s *storage) Health(ctx context.Context) error { return s.db.Pool().Ping(ctx) }

// ----------------------------------------------------------------- models

func sidOf(request any) string {
	switch r := request.(type) {
	case *authRequest:
		return r.SID
	case *refreshTokenRequest:
		return r.SID
	}
	return ""
}

func authOf(request any) (time.Time, []string) {
	switch r := request.(type) {
	case *authRequest:
		return r.AuthTime, r.AMR
	case *refreshTokenRequest:
		return r.AuthTime, r.AMR
	}
	return time.Time{}, nil
}

// authRequest adapts a stored request to op.AuthRequest.
type authRequest struct{ *store.AuthRequest }

func (a *authRequest) GetID() string                       { return a.ID }
func (a *authRequest) GetACR() string                      { return "" }
func (a *authRequest) GetAMR() []string                    { return a.AMR }
func (a *authRequest) GetAudience() []string               { return []string{a.ClientID} }
func (a *authRequest) GetAuthTime() time.Time              { return a.AuthTime }
func (a *authRequest) GetClientID() string                 { return a.ClientID }
func (a *authRequest) GetNonce() string                    { return a.Nonce }
func (a *authRequest) GetRedirectURI() string              { return a.RedirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType  { return oidc.ResponseType(a.ResponseType) }
func (a *authRequest) GetResponseMode() oidc.ResponseMode  { return oidc.ResponseMode(a.ResponseMode) }
func (a *authRequest) GetScopes() []string                 { return a.Scopes }
func (a *authRequest) GetState() string                    { return a.State }
func (a *authRequest) GetSubject() string                  { return a.Subject }
func (a *authRequest) Done() bool                          { return a.AuthRequest.Done }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{Challenge: a.CodeChallenge, Method: oidc.CodeChallengeMethod(a.CodeChallengeMethod)}
}

// refreshTokenRequest adapts a stored refresh token to op.RefreshTokenRequest.
type refreshTokenRequest struct {
	*store.RefreshToken
	scopes []string
}

func (r *refreshTokenRequest) GetAMR() []string            { return r.AMR }
func (r *refreshTokenRequest) GetAudience() []string       { return []string{r.ClientID} }
func (r *refreshTokenRequest) GetAuthTime() time.Time      { return r.AuthTime }
func (r *refreshTokenRequest) GetClientID() string         { return r.ClientID }
func (r *refreshTokenRequest) GetScopes() []string         { return r.scopes }
func (r *refreshTokenRequest) GetSubject() string          { return r.Subject }
func (r *refreshTokenRequest) SetCurrentScopes(s []string) { r.scopes = s }

// client adapts a stored client to op.Client.
type client struct {
	*store.Client
	issuer string
	dev    bool
}

func (c *client) GetID() string                    { return c.ClientID }
func (c *client) RedirectURIs() []string           { return c.Client.RedirectURIs }
func (c *client) PostLogoutRedirectURIs() []string { return c.Client.PostLogoutRedirectURIs }
func (c *client) ApplicationType() op.ApplicationType {
	switch c.Client.ApplicationType {
	case "native":
		return op.ApplicationTypeNative
	case "user_agent":
		return op.ApplicationTypeUserAgent
	}
	return op.ApplicationTypeWeb
}
func (c *client) AuthMethod() oidc.AuthMethod {
	if c.SecretHash == "" {
		return oidc.AuthMethodNone
	}
	return oidc.AuthMethodPost
}
func (c *client) ResponseTypes() []oidc.ResponseType { return []oidc.ResponseType{oidc.ResponseTypeCode} }
func (c *client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
}
func (c *client) LoginURL(id string) string {
	return c.issuer + "/login?authRequestID=" + url.QueryEscape(id)
}
func (c *client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }
func (c *client) IDTokenLifetime() time.Duration      { return IDTokenTTL }
func (c *client) DevMode() bool                       { return c.dev }
func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *client) IsScopeAllowed(scope string) bool      { return c.AllowsScope(scope) }
func (c *client) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *client) ClockSkew() time.Duration             { return 0 }

// callbackURL is where a completed authorization request resumes inside
// zitadel/oidc, which issues the code.
func callbackURL(issuer, id string) string {
	return issuer + "/oauth/authorize/callback?id=" + url.QueryEscape(id)
}

// errAuthRequest lets a stored request carry an error back to its client.
type errAuthRequest struct{ *store.AuthRequest }

func (e errAuthRequest) GetRedirectURI() string             { return e.RedirectURI }
func (e errAuthRequest) GetResponseType() oidc.ResponseType { return oidc.ResponseType(e.ResponseType) }
func (e errAuthRequest) GetState() string                   { return e.State }
func (e errAuthRequest) GetResponseMode() oidc.ResponseMode { return oidc.ResponseMode(e.ResponseMode) }
