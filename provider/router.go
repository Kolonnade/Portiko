package provider

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"

	"github.com/Kolonnade/Portiko/internal/store"
	kitprotocol "github.com/Kolonnade/Portiko/protocol"
)

const maxAccounts = store.MaxAccountsPerBrowser

// Deps is everything the router needs.
type Deps struct {
	OpenID    http.Handler
	Discovery *Discovery
	Auth      *Auth
	Login     *Login
	Pages     *Pages
	Health    http.HandlerFunc
}

// Router builds the complete HTTP surface.
func Router(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", d.Health)

	// The protocol itself comes from zitadel/oidc: authorize, token, userinfo,
	// revocation, introspection, end session, discovery and the key set.
	mux.Handle("/oauth/", d.OpenID)
	mux.Handle("GET /.well-known/openid-configuration", servedOnly(d.OpenID))
	mux.Handle("GET /.well-known/jwks.json", d.OpenID)

	// Discovery sits outside the version middleware on purpose: a client reads
	// it precisely to learn which versions exist.
	mux.HandleFunc("GET "+kitprotocol.WellKnownPath, d.Discovery.Configuration)
	mux.HandleFunc("GET "+kitprotocol.LegacyWellKnownPath, d.Discovery.Configuration)

	api := http.NewServeMux()
	api.HandleFunc("GET /accounts/v1/ping", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"protocol": kitprotocol.Name, "version": NegotiatedVersion(r).String()})
	})
	api.HandleFunc("POST /accounts/v1/register/start", d.Auth.StartRegistration)
	api.HandleFunc("POST /accounts/v1/register/verify", d.Auth.VerifyCode)
	api.HandleFunc("POST /accounts/v1/register/finish", d.Auth.FinishRegistration)
	api.HandleFunc("GET /accounts/v1/login/start", d.Auth.StartLogin)
	api.HandleFunc("POST /accounts/v1/login/finish", d.Auth.FinishLogin)
	api.HandleFunc("POST /accounts/v1/logout", d.Auth.Logout)
	api.HandleFunc("POST /accounts/v1/logout/all", d.Auth.LogoutAll)
	api.HandleFunc("POST /accounts/v1/default", d.Auth.SetDefault)
	api.HandleFunc("POST /accounts/v1/profile", d.Auth.UpdateProfile)
	api.HandleFunc("GET /accounts/v1/session", d.Auth.Session)
	mux.Handle("/accounts/", VersionMiddleware(api))

	mux.HandleFunc("GET /login", d.Login.Start)
	mux.HandleFunc("POST /login/select", d.Login.Select)

	mux.HandleFunc("GET /signin", d.Pages.SignIn)
	mux.HandleFunc("GET /profile", d.Pages.ProfileRedirect)
	mux.HandleFunc("GET /u/{n}/{$}", d.Pages.Home)
	mux.HandleFunc("GET /u/{n}/profile", d.Pages.Profile)
	mux.HandleFunc("GET /{$}", d.Pages.Root)
	return mux
}

// Discovery serves the Portiko configuration document.
type Discovery struct{ cfg *Config }

// Configuration serves the protocol version range. OpenID Connect discovery
// covers everything else and comes from zitadel/oidc.
func (d *Discovery) Configuration(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, kitprotocol.Configuration{
		Protocol:          kitprotocol.Name,
		VersionsSupported: versionStrings(),
		VersionMinimum:    Minimum.String(),
		VersionPreferred:  Preferred.String(),
		Issuer:            d.cfg.Issuer,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// unserved lists discovery fields zitadel/oidc fills in for features Portiko
// does not provide.
var unserved = []string{"device_authorization_endpoint", "check_session_iframe"}

// servedOnly removes from the OpenID discovery document every endpoint Portiko
// does not serve. A client written against discovery takes an advertised URL at
// its word, so an endpoint appears only in the change that implements it.
func servedOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		var doc map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &doc) != nil {
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(rec.Body.Bytes())
			return
		}
		for _, k := range unserved {
			delete(doc, k)
		}
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(doc)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})
}
