//go:build conformance

// Package conformance is the harness the OpenID Foundation's conformance suite
// runs against. It is test-only: it builds only with the conformance tag, and it
// is never part of the portiko binary.
//
// The suite drives the authorization endpoint with a headless browser that
// cannot create or use a passkey. The harness embeds the provider unchanged,
// enrolls one account through the real registration ceremony with a virtual
// authenticator, and, when the suite's browser lands on the sign-in page for an
// authorization request, performs the real login ceremony on that browser's
// behalf, with its cookies. It adds no route, flag or bypass to the provider:
// every other request is served by the provider's own handler, and the sign-in
// itself goes through the same login/start and login/finish endpoints a person's
// browser calls. See docs/conformance.md.
package conformance

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"

	"github.com/descope/virtualwebauthn"

	"github.com/Kolonnade/Portiko/internal/config"
	"github.com/Kolonnade/Portiko/provider"
)

// Email is the address of the one account the harness enrolls.
const Email = "conformance@example.com"

// Client is one of the suite's clients.
type Client struct {
	ID, Secret string
}

// Config is what a run needs.
type Config struct {
	// Issuer is the harness's HTTPS base URL, as the suite's containers reach it.
	// It is also the WebAuthn origin, and its host is the RP ID.
	Issuer string
	// DatabaseURL is an empty database, or one left by an earlier run of this
	// harness; it is migrated, and every client is redeclared.
	DatabaseURL string
	// RedirectURIs are the suite's callback URLs, registered on every client.
	RedirectURIs []string
	// Clients are registered as confidential, first-party clients.
	Clients []Client
}

// Harness is the provider plus the virtual authenticator that signs in for the
// suite's browser.
type Harness struct {
	p      *provider.Provider
	issuer string
	rp     virtualwebauthn.RelyingParty
	mail   *codeMailer

	mu   sync.Mutex
	auth virtualwebauthn.Authenticator
	cred virtualwebauthn.Credential
	// signIns counts the ceremonies performed for the suite's browser.
	signIns int
}

// New migrates the database, starts the provider, registers the clients and
// enrolls the test account.
func New(ctx context.Context, c Config) (*Harness, error) {
	iss, err := url.Parse(c.Issuer)
	if err != nil || iss.Scheme != "https" || iss.Hostname() == "" {
		return nil, fmt.Errorf("conformance: issuer must be an https URL, got %q", c.Issuer)
	}
	if len(c.Clients) == 0 || len(c.RedirectURIs) == 0 {
		return nil, errors.New("conformance: at least one client and one redirect URI are required")
	}
	if _, err := provider.Migrate(ctx, c.DatabaseURL); err != nil {
		return nil, err
	}

	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	issuer := strings.TrimSuffix(c.Issuer, "/")
	cfg := &provider.Config{
		Issuer:            issuer,
		DatabaseURL:       c.DatabaseURL,
		ServiceName:       "Portiko Conformance",
		WebAuthnRPID:      iss.Hostname(),
		WebAuthnRPOrigins: []string{issuer},
		Registration:      config.RegistrationOpen,
		CryptoKey:         key,
	}
	mail := &codeMailer{codes: map[string]string{}}
	p, err := provider.New(ctx, cfg, provider.Options{Mailer: mail})
	if err != nil {
		return nil, err
	}
	h := &Harness{
		p: p, issuer: issuer, mail: mail,
		rp: virtualwebauthn.RelyingParty{Name: cfg.ServiceName, ID: cfg.WebAuthnRPID, Origin: issuer},
		// A synced passkey, the common case in practice.
		auth: virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
			BackupEligible: true, BackupState: true,
		}),
	}
	for _, cl := range c.Clients {
		if err := p.RegisterClient(ctx, provider.Client{
			ID: cl.ID, Secret: cl.Secret, Audience: originOf(c.RedirectURIs[0]),
			DisplayName: "Conformance suite " + cl.ID, RedirectURIs: c.RedirectURIs,
			Scopes:     []string{"openid", "profile", "email", "offline_access"},
			FirstParty: true,
		}); err != nil {
			p.Close()
			return nil, err
		}
	}
	if err := h.enroll(); err != nil {
		p.Close()
		return nil, fmt.Errorf("conformance: enrolling %s: %w", Email, err)
	}
	return h, nil
}

// Close stops the provider.
func (h *Harness) Close() { h.p.Close() }

// SignIns is how many times the harness has signed in for the suite.
func (h *Harness) SignIns() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.signIns
}

// ServeHTTP serves the provider, except that the sign-in page for an
// authorization request is answered by a passkey ceremony instead of a page.
//
// The harness needs a root issuer (no path): it intercepts /signin and calls
// /accounts/v1/* unprefixed.
func (h *Harness) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/signin" && r.URL.Query().Get("authRequestID") != "" {
		h.signIn(w, r)
		return
	}
	h.p.Handler().ServeHTTP(w, r)
}

// signIn does what signin.html does after a person uses their passkey:
// login/start, an assertion, login/finish with the authorization request, then
// on to wherever the provider says. It runs on the browser's own cookies and
// address, and the browser receives every cookie the provider set.
func (h *Harness) signIn(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("authRequestID")
	start := h.call(r, http.MethodGet, "/accounts/v1/login/start", "")
	if start.Code != http.StatusOK {
		h.relay(w, start, "login/start")
		return
	}
	options, err := virtualwebauthn.ParseAssertionOptions(start.Body.String())
	if err != nil {
		http.Error(w, "conformance harness: parsing assertion options: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.mu.Lock()
	assertion := virtualwebauthn.CreateAssertionResponse(h.rp, h.auth, h.cred, *options)
	h.signIns++
	h.mu.Unlock()

	fin := h.call(r, http.MethodPost, "/accounts/v1/login/finish?authRequestID="+url.QueryEscape(id), assertion)
	if fin.Code != http.StatusOK {
		h.relay(w, fin, "login/finish")
		return
	}
	var out struct {
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal(fin.Body.Bytes(), &out); err != nil || out.Redirect == "" {
		http.Error(w, "conformance harness: login/finish gave no redirect", http.StatusInternalServerError)
		return
	}
	for _, rec := range []*httptest.ResponseRecorder{start, fin} {
		for _, c := range rec.Result().Header.Values("Set-Cookie") {
			w.Header().Add("Set-Cookie", c)
		}
	}
	slog.Info("conformance: signed in for the suite", "authRequestID", id)
	http.Redirect(w, r, out.Redirect, http.StatusFound)
}

// call runs one request through the provider in-process, as the browser that
// made r.
func (h *Harness) call(r *http.Request, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(r.Context(), method, h.issuer+path, strings.NewReader(body))
	req.RemoteAddr = r.RemoteAddr
	req.Header.Set("User-Agent", r.UserAgent())
	if ck := r.Header.Get("Cookie"); ck != "" {
		req.Header.Set("Cookie", ck)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.p.Handler().ServeHTTP(rec, req)
	return rec
}

// relay passes a failed step back to the browser, so the suite's log shows it.
func (h *Harness) relay(w http.ResponseWriter, rec *httptest.ResponseRecorder, step string) {
	slog.Warn("conformance: sign-in step failed", "step", step, "status", rec.Code, "body", rec.Body.String())
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(rec.Code)
	_, _ = fmt.Fprintf(w, "conformance harness: %s answered %d: %s", step, rec.Code, rec.Body.String())
}

// enroll creates the test account: register/start, the emailed code,
// register/verify, a virtual attestation, register/finish.
func (h *Harness) enroll() error {
	r := httptest.NewRequest(http.MethodGet, h.issuer+"/", nil)
	post := func(path string, v any) (*httptest.ResponseRecorder, error) {
		blob, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		return h.call(r, http.MethodPost, path, string(blob)), nil
	}
	if rec, err := post("/accounts/v1/register/start", map[string]string{"email": Email}); err != nil {
		return err
	} else if rec.Code != http.StatusAccepted {
		return fmt.Errorf("register/start: %d %s", rec.Code, rec.Body)
	}
	code, ok := h.mail.code(Email)
	if !ok {
		return errors.New("no code was sent")
	}
	rec, err := post("/accounts/v1/register/verify", map[string]string{"email": Email, "code": code})
	if err != nil {
		return err
	}
	if rec.Code != http.StatusOK {
		return fmt.Errorf("register/verify: %d %s", rec.Code, rec.Body)
	}
	var verified struct {
		CreationOptions json.RawMessage `json:"creation_options"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &verified); err != nil {
		return err
	}
	options, err := virtualwebauthn.ParseAttestationOptions(string(verified.CreationOptions))
	if err != nil {
		return err
	}
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	attestation := virtualwebauthn.CreateAttestationResponse(h.rp, h.auth, cred, *options)
	fin := h.call(r, http.MethodPost, "/accounts/v1/register/finish", attestation)
	if fin.Code != http.StatusOK {
		return fmt.Errorf("register/finish: %d %s", fin.Code, fin.Body)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	// A discoverable sign-in identifies the account by its user handle, as a
	// platform passkey does.
	h.auth.Options.UserHandle = []byte(options.UserID)
	h.auth.AddCredential(cred)
	h.cred = cred
	return nil
}

// codeMailer keeps the one-time codes instead of sending them.
type codeMailer struct {
	mu    sync.Mutex
	codes map[string]string
}

func (m *codeMailer) SendCode(to, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[to] = code
	return nil
}

func (m *codeMailer) SendPasskeyAdded(string, provider.PasskeyNotice) error { return nil }

func (m *codeMailer) code(to string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[to]
	return c, ok
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host
}
