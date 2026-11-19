// Package rp is the relying-party half of Portiko: everything a website needs to
// sign people in against a Portiko provider.
//
// It is built on zitadel/oidc's relying party, which handles discovery, PKCE,
// state, the code exchange, ID-token verification and refresh. What this package
// adds is the part every site otherwise writes by hand: a server-side session
// with the tokens kept off the browser, refresh that happens once however many
// requests race for it, and receivers for sign-outs and profile changes pushed by
// the provider.
package rp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client"
	zrp "github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/sync/singleflight"

	"github.com/Kolonnade/Portiko/internal/localpath"
	"github.com/Kolonnade/Portiko/protocol"
	"github.com/Kolonnade/Portiko/rp/session"
	"github.com/Kolonnade/Portiko/verify"
)

// Config configures a relying party.
type Config struct {
	// Issuer is the provider's base URL, e.g. https://accounts.example.com.
	Issuer string
	// ClientID and ClientSecret identify this site to the provider.
	ClientID     string
	ClientSecret string
	// RedirectURL must exactly match a registered redirect URI.
	RedirectURL string
	// Sessions stores signed-in browsers. Required.
	Sessions session.Store
	// Scopes requested at sign-in. "openid" and "offline_access" are always
	// included; the second is what makes the provider issue a refresh token.
	Scopes []string
	// HTTPClient is used for discovery, keys and token requests.
	HTTPClient *http.Client
	// Insecure allows http:// and drops the Secure cookie flag. Local development only.
	Insecure bool
	// CookieKey protects the short-lived cookies that carry a sign-in across the
	// redirect: its state, PKCE verifier and nonce. At least 32 bytes, and the
	// same on every replica of the site.
	CookieKey []byte
	// OnSignIn runs once per sign-in, after the tokens verify and before the
	// browser is redirected on. This is where a site provisions its own record
	// for the person; an error fails the sign-in rather than leaving a session
	// pointing at a person the site never recorded.
	OnSignIn func(ctx context.Context, s *session.Session) error
}

// Client is a configured relying party.
type Client struct {
	cfg     Config
	rp      zrp.RelyingParty
	cookies *httphelper.CookieHandler
	keys    *verify.KeySet
	issuer  string
	version protocol.Version
	flight  singleflight.Group
}

const (
	flowCookie   = "portiko_rp_flow"
	// flowTTL is how long a sign-in may take, from leaving the site to coming
	// back. It matches the provider's longest authorization request
	// (store.AuthRequestMaxLife): a first sign-up includes reading an email.
	flowTTL = 2 * time.Hour
	leeway       = 30 * time.Second
	sessionTTL   = 30 * 24 * time.Hour
	fetchTimeout = 10 * time.Second
	// endSessionTimeout bounds the call to the provider at sign-out, so a
	// provider that is down delays leaving the site by seconds, not minutes.
	endSessionTimeout = 3 * time.Second
)

// New discovers the provider and returns a client.
//
// Discovery and the protocol-version check happen at startup: a site that
// cannot speak to its identity provider should fail to boot with a clear
// message, not fail at a person's first sign-in.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("rp: Issuer, ClientID and RedirectURL are required")
	}
	if cfg.Sessions == nil {
		return nil, errors.New("rp: a session store is required")
	}
	if len(cfg.CookieKey) < 32 {
		return nil, errors.New("rp: CookieKey must be at least 32 bytes")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: fetchTimeout}
	}
	issuer := strings.TrimSuffix(cfg.Issuer, "/")

	cookieOpts := []httphelper.CookieHandlerOpt{
		httphelper.WithSameSite(http.SameSiteLaxMode), httphelper.WithMaxAge(int(flowTTL / time.Second)),
	}
	if cfg.Insecure {
		cookieOpts = append(cookieOpts, httphelper.WithUnsecure())
	}
	cookies := httphelper.NewCookieHandler(deriveKey(cfg.CookieKey, "hash"), deriveKey(cfg.CookieKey, "encrypt"), cookieOpts...)

	disc, err := client.Discover(ctx, issuer, cfg.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("rp: discovery: %w", err)
	}
	if disc.Issuer != issuer {
		// A discovery document naming a different issuer is either misconfigured
		// or an attempt to point this site at someone else's keys.
		return nil, fmt.Errorf("rp: discovery issuer %q does not match %q", disc.Issuer, issuer)
	}
	version, err := negotiate(ctx, cfg.HTTPClient, issuer)
	if err != nil {
		return nil, err
	}

	scopes := []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess}
	for _, s := range cfg.Scopes {
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	relyingParty, err := zrp.NewRelyingPartyOIDC(ctx, issuer, cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL, scopes,
		zrp.WithPKCE(cookies),
		zrp.WithHTTPClient(cfg.HTTPClient),
		zrp.WithVerifierOpts(zrp.WithNonce(nonceFromContext), zrp.WithIssuedAtOffset(leeway)),
		zrp.WithUnauthorizedHandler(func(w http.ResponseWriter, _ *http.Request, _ string, _ string) {
			http.Error(w, "sign-in failed", http.StatusUnauthorized)
		}),
		zrp.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, errorType string, _ string, _ string) {
			http.Error(w, "sign-in failed: "+errorType, http.StatusUnauthorized)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("rp: %w", err)
	}
	return &Client{
		cfg: cfg, rp: relyingParty, cookies: cookies,
		keys: verify.NewKeySet(disc.JwksURI, cfg.HTTPClient), issuer: issuer, version: version,
	}, nil
}

// negotiate reads the provider's protocol version range, falling back to the
// path the proof of concept used.
func negotiate(ctx context.Context, hc *http.Client, issuer string) (protocol.Version, error) {
	var pc protocol.Configuration
	err := fetchJSON(ctx, hc, issuer+protocol.WellKnownPath, &pc)
	if err != nil {
		err = fetchJSON(ctx, hc, issuer+protocol.LegacyWellKnownPath, &pc)
	}
	if err != nil {
		return protocol.Version{}, fmt.Errorf("rp: protocol discovery: %w", err)
	}
	v, err := protocol.Negotiate(protocol.VersionMax, pc.Versions())
	if err != nil {
		return protocol.Version{}, fmt.Errorf("rp: no common protocol version with %s (this build speaks %s–%s): %w",
			issuer, protocol.VersionMin, protocol.VersionMax, err)
	}
	return v, nil
}

// Version reports the negotiated protocol version.
func (c *Client) Version() protocol.Version { return c.version }

// flowState is what a sign-in carries across the redirect, encrypted in a
// short-lived cookie rather than held in this process: any replica of the site
// can finish a sign-in another one started.
type flowState struct {
	State     string `json:"s"`
	Nonce     string `json:"n"`
	ReturnTo  string `json:"r"`
	Prompt    string `json:"p,omitempty"`
	LoginHint string `json:"h,omitempty"`
	// Restarted is set on a sign-in started again after the provider answered
	// login_required, so a provider that keeps answering it is not looped.
	Restarted bool `json:"x,omitempty"`
}

type nonceKey struct{}

func nonceFromContext(ctx context.Context) string {
	n, _ := ctx.Value(nonceKey{}).(string)
	return n
}

// promptCreate is OpenID Connect's prompt=create; zitadel/oidc has no constant.
const promptCreate = "create"

// LoginHandler starts a sign-in. ?return_to= names a local path to come back
// to; ?prompt=select_account asks the provider to offer its account chooser,
// ?prompt=login asks it to sign in afresh, ?prompt=create asks it to open on
// account creation, and ?login_hint= names the account to prefer.
func (c *Client) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f := flowState{ReturnTo: localPath(q.Get("return_to")), LoginHint: q.Get("login_hint")}
		if p := q.Get("prompt"); p == oidc.PromptSelectAccount || p == oidc.PromptLogin || p == promptCreate {
			f.Prompt = p
		}
		c.startSignIn(w, r, f)
	})
}

// startSignIn sends the browser to the provider with fresh state and nonce,
// remembering f in the flow cookie.
func (c *Client) startSignIn(w http.ResponseWriter, r *http.Request, f flowState) {
	state, err1 := randomToken(32)
	nonce, err2 := randomToken(32)
	if err1 != nil || err2 != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	f.State, f.Nonce = state, nonce
	flow, _ := json.Marshal(f)
	if err := c.cookies.SetCookie(w, flowCookie, string(flow)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	params := []zrp.URLParamOpt{zrp.WithURLParam("nonce", nonce)}
	if f.Prompt != "" {
		params = append(params, zrp.WithPromptURLParam(f.Prompt))
	}
	if f.LoginHint != "" {
		params = append(params, zrp.WithURLParam("login_hint", f.LoginHint))
	}
	zrp.AuthURLHandler(func() string { return state }, c.rp, params...).ServeHTTP(w, r)
}

// CallbackHandler completes a sign-in: it checks the state, redeems the code,
// verifies both tokens, and establishes a local session.
func (c *Client) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := c.cookies.CheckCookie(r, flowCookie)
		var flow flowState
		if err != nil || json.Unmarshal([]byte(raw), &flow) != nil || flow.State == "" || flow.State != r.URL.Query().Get("state") {
			http.Error(w, "sign-in failed: unknown or expired sign-in", http.StatusBadRequest)
			return
		}
		c.cookies.DeleteCookie(w, flowCookie)
		// The provider gave up on this sign-in, typically because the person
		// took longer than it keeps a request. Start again, once, with the same
		// destination: the person is usually signed in at the provider by now,
		// so this costs them nothing and keeps where they were going. The
		// prompt is not repeated: login or create would ask someone who has just
		// signed in, or just made their account, to do it again.
		if r.URL.Query().Get("error") == string(oidc.LoginRequired) && !flow.Restarted {
			c.startSignIn(w, r, flowState{ReturnTo: flow.ReturnTo, LoginHint: flow.LoginHint, Restarted: true})
			return
		}
		ctx := context.WithValue(r.Context(), nonceKey{}, flow.Nonce)
		zrp.CodeExchangeHandler(func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], _ string, _ zrp.RelyingParty) {
			c.finishSignIn(w, r, tokens, flow.ReturnTo)
		}, c.rp).ServeHTTP(w, r.WithContext(ctx))
	})
}

func (c *Client) finishSignIn(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], returnTo string) {
	ctx := r.Context()
	if tokens.IDTokenClaims == nil {
		http.Error(w, "sign-in failed", http.StatusUnauthorized)
		return
	}
	claims, err := c.verifyAccess(ctx, tokens.AccessToken)
	if err != nil || claims.Subject != tokens.IDTokenClaims.Subject {
		http.Error(w, "sign-in failed", http.StatusUnauthorized)
		return
	}
	id, err := session.NewID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sess := &session.Session{
		ID:             id,
		Subject:        claims.Subject,
		Email:          claims.Email,
		Name:           claims.Name,
		Avatar:         claims.Avatar,
		SID:            claims.SessionID,
		ProfileVersion: claims.UpdatedAt,
		AccessToken:    tokens.AccessToken,
		RefreshToken:   tokens.RefreshToken,
		IDToken:        tokens.IDToken,
		AccessExpiry:   tokens.Expiry,
		ExpiresAt:      time.Now().Add(sessionTTL),
	}
	if c.cfg.OnSignIn != nil {
		if err := c.cfg.OnSignIn(ctx, sess); err != nil {
			http.Error(w, "sign-in failed", http.StatusInternalServerError)
			return
		}
	}
	if err := c.cfg.Sessions.Put(ctx, sess); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	session.SetCookie(w, id, sess.ExpiresAt, !c.cfg.Insecure)
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func (c *Client) verifyAccess(ctx context.Context, token string) (*verify.Claims, error) {
	return verify.AccessToken(ctx, token, verify.Options{
		Issuer: c.issuer, Audience: c.cfg.ClientID, Keys: c.keys, Leeway: leeway,
	})
}

// LogoutHandler drops this site's session. It deliberately does not sign the
// account out of the provider: leaving one site should not sign a person out of
// every other one.
func (c *Client) LogoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ck, err := r.Cookie(session.CookieName); err == nil {
			_ = c.cfg.Sessions.Delete(r.Context(), ck.Value)
		}
		session.ClearCookie(w, !c.cfg.Insecure)
		http.Redirect(w, r, "/", http.StatusFound)
	})
}

// EndSessionHandler signs the person out of this site and ends the account's
// session at the provider, then redirects to after (a local path).
//
// Unlike LogoutHandler, the account is signed out at the provider too, so the
// next sign-in asks again. Only this account ends: other accounts signed in to
// the same browser stay signed in, and the provider tells the other sites that
// held this account's session through back-channel logout.
//
// With a site session that holds an ID token, the provider is called server to
// server with it as id_token_hint, and the browser never visits the provider.
// If that call fails, the site's own session still ends.
//
// Without one (the site restarted with an in-memory store, the session expired,
// or the cookie is gone) the site cannot say which account to end. The browser
// is sent to the provider's end_session_endpoint instead, with client_id and
// post_logout_redirect_uri, so the provider ends the sessions in that browser
// that signed in to this site and sends it back to after. Otherwise sign-out
// would end nothing, and on a shared computer the next person could pick the
// previous account at the provider without a passkey. Register the site's
// origin followed by after (e.g. https://site.example/welcome) as a
// post-logout redirect URI, or the provider refuses the redirect.
func (c *Client) EndSessionHandler(after string) http.Handler {
	after = localPath(after)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ended := false
		if ck, err := r.Cookie(session.CookieName); err == nil {
			if sess, err := c.cfg.Sessions.Get(r.Context(), ck.Value); err == nil && sess.IDToken != "" {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), endSessionTimeout)
				if _, err := zrp.EndSession(ctx, c.rp, sess.IDToken, "", "", "", nil); err != nil {
					slog.WarnContext(ctx, "rp: ending the provider session", "err", err)
				}
				cancel()
				ended = true
			}
			_ = c.cfg.Sessions.Delete(r.Context(), ck.Value)
		}
		session.ClearCookie(w, !c.cfg.Insecure)
		if !ended {
			if to := c.frontChannelEndSession(after); to != "" {
				http.Redirect(w, r, to, http.StatusFound)
				return
			}
		}
		http.Redirect(w, r, after, http.StatusFound)
	})
}

// frontChannelEndSession is the provider's end-session URL for a browser this
// site holds no session for, or "" when the provider advertises none.
func (c *Client) frontChannelEndSession(after string) string {
	endpoint := c.rp.GetEndSessionEndpoint()
	if endpoint == "" {
		return ""
	}
	q := url.Values{"client_id": {c.cfg.ClientID}}
	if origin := originOf(c.cfg.RedirectURL); origin != "" {
		q.Set("post_logout_redirect_uri", origin+after)
	}
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}
	return endpoint + sep + q.Encode()
}

// originOf is scheme://host of an absolute URL, or "".
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

type ctxKey struct{}

// SessionFrom returns the session attached by RequireUser.
func SessionFrom(ctx context.Context) (*session.Session, bool) {
	s, ok := ctx.Value(ctxKey{}).(*session.Session)
	return s, ok
}

// RequireUser runs next only for a signed-in person, refreshing an expiring
// access token first, and sends anyone else to sign in.
func (c *Client) RequireUser(next http.Handler) http.Handler {
	return c.requireUser(next, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/auth/login?return_to="+urlQueryEscape(r.URL.RequestURI()), http.StatusFound)
	})
}

// RequireUserAPI is RequireUser for endpoints a script calls: no session is a
// 401 in JSON, not a redirect a fetch() would follow into an HTML page.
func (c *Client) RequireUserAPI(next http.Handler) http.Handler {
	return c.requireUser(next, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"not signed in"}`))
	})
}

func (c *Client) requireUser(next http.Handler, anonymous http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ck, err := r.Cookie(session.CookieName)
		if err != nil {
			anonymous(w, r)
			return
		}
		sess, err := c.cfg.Sessions.Get(ctx, ck.Value)
		if err != nil {
			anonymous(w, r)
			return
		}
		if sess.AccessExpired() {
			fresh, err := c.refreshOnce(ctx, sess.ID)
			if err != nil {
				_ = c.cfg.Sessions.Delete(ctx, sess.ID)
				anonymous(w, r)
				return
			}
			sess = fresh
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, ctxKey{}, sess)))
	})
}

// refreshOnce refreshes a session's tokens at most once however many requests
// arrive together.
//
// Refresh tokens rotate, so two requests presenting the same one would have the
// second refused and the person signed out at random. Within this process the
// requests share one refresh. Across replicas, a refusal is followed by one
// re-read of the session, which finds the tokens the other replica stored.
func (c *Client) refreshOnce(ctx context.Context, id string) (*session.Session, error) {
	v, err, _ := c.flight.Do(id, func() (any, error) {
		ctx := context.WithoutCancel(ctx)
		sess, err := c.cfg.Sessions.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if !sess.AccessExpired() {
			return sess, nil
		}
		if err := c.refresh(ctx, sess); err != nil {
			if again, gerr := c.cfg.Sessions.Get(ctx, id); gerr == nil &&
				again.RefreshToken != sess.RefreshToken && !again.AccessExpired() {
				return again, nil
			}
			return nil, err
		}
		return sess, nil
	})
	if err != nil {
		return nil, err
	}
	cp := *v.(*session.Session)
	return &cp, nil
}

func (c *Client) refresh(ctx context.Context, sess *session.Session) error {
	if sess.RefreshToken == "" {
		return errors.New("rp: no refresh token")
	}
	tokens, err := zrp.RefreshTokens[*oidc.IDTokenClaims](ctx, c.rp, sess.RefreshToken, "", "")
	if err != nil {
		return err
	}
	// Verified like the first token, not trusted because it came back from the
	// token endpoint: the claims below are about to be shown to the person.
	claims, err := c.verifyAccess(ctx, tokens.AccessToken)
	if err != nil {
		return err
	}
	if claims.Subject != sess.Subject {
		return errors.New("rp: refreshed token names a different subject")
	}
	sess.Email = claims.Email
	// A profile change pushed to this site can be newer than a token that was
	// already in flight; the older one must not win.
	if claims.UpdatedAt >= sess.ProfileVersion {
		sess.Name, sess.Avatar, sess.ProfileVersion = claims.Name, claims.Avatar, claims.UpdatedAt
	}
	if claims.SessionID != "" {
		sess.SID = claims.SessionID
	}
	sess.AccessToken = tokens.AccessToken
	sess.AccessExpiry = tokens.Expiry
	if tokens.RefreshToken != "" {
		sess.RefreshToken = tokens.RefreshToken
	}
	if tokens.IDToken != "" {
		sess.IDToken = tokens.IDToken
	}
	return c.cfg.Sessions.Put(ctx, sess)
}

func fetchJSON(ctx context.Context, hc *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set(protocol.HeaderVersion, protocol.VersionMax.String())
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", url, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// localPath keeps return_to to a path on this site, so it cannot become an open
// redirect.
func localPath(p string) string { return localpath.Or(p, "/") }

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// deriveKey separates the cookie key into independent keys for signing and
// encrypting, so one secret configures both without reusing it.
func deriveKey(secret []byte, purpose string) []byte {
	h := sha256.New()
	h.Write([]byte("portiko rp cookie " + purpose + "\x00"))
	h.Write(secret)
	return h.Sum(nil)
}

func urlQueryEscape(s string) string {
	return strings.NewReplacer("%", "%25", "&", "%26", "+", "%2B", "#", "%23", " ", "%20", "?", "%3F", "=", "%3D").Replace(s)
}
