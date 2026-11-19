package provider_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/Kolonnade/Portiko/internal/store"
)

// registerFor signs up with every ceremony request naming query, and returns
// where the provider says to go next.
func (h *harness) registerFor(email, query string) string {
	h.t.Helper()
	start := map[string]string{"email": email, "bootstrap_code": h.cfg.BootstrapCode}
	if resp := h.post("/accounts/v1/register/start"+query, start); resp.StatusCode != http.StatusAccepted {
		h.t.Fatalf("register/start: %s", bodyString(h.t, resp))
	}
	resp := h.post("/accounts/v1/register/verify"+query, map[string]string{"email": email, "code": h.latestCode(email)})
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("register/verify: %d %s", resp.StatusCode, bodyString(h.t, resp))
	}
	var verified struct {
		CreationOptions json.RawMessage `json:"creation_options"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&verified)
	resp.Body.Close()
	options, err := virtualwebauthn.ParseAttestationOptions(string(verified.CreationOptions))
	if err != nil {
		h.t.Fatalf("parsing attestation options: %v", err)
	}
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	attestation := virtualwebauthn.CreateAttestationResponse(h.rp, h.auth, credential, *options)
	fin, err := h.client.Post(h.srv.URL+h.prefix+"/accounts/v1/register/finish"+query, "application/json", strings.NewReader(attestation))
	if err != nil {
		h.t.Fatalf("register/finish: %v", err)
	}
	if fin.StatusCode != http.StatusOK {
		h.t.Fatalf("register/finish: %d %s", fin.StatusCode, bodyString(h.t, fin))
	}
	var out struct {
		Redirect string `json:"redirect"`
	}
	_ = json.NewDecoder(fin.Body).Decode(&out)
	fin.Body.Close()
	h.auth.AddCredential(credential)
	return out.Redirect
}

// pendingAuthRequest starts a site's sign-in with no account signed in and
// returns the request's id from the sign-in page it lands on.
func (h *harness) pendingAuthRequest(s *site) string {
	h.t.Helper()
	_, resp := h.authorize(s.clientID, s.url+"/auth/callback", "openid", nil)
	if resp == nil {
		h.t.Fatal("authorize went straight to the site")
	}
	resp.Body.Close()
	id := resp.Request.URL.Query().Get("authRequestID")
	if id == "" {
		h.t.Fatalf("no authRequestID on %s", resp.Request.URL)
	}
	return id
}

func (h *harness) authRequestTimes(id string) (created, expires time.Time) {
	h.t.Helper()
	if err := h.db.Pool().QueryRow(context.Background(),
		`SELECT created_at, expires_at FROM auth_requests WHERE id = $1`, id).Scan(&created, &expires); err != nil {
		h.t.Fatal(err)
	}
	return created, expires
}

func (h *harness) execSQL(sql string, args ...any) {
	h.t.Helper()
	if _, err := h.db.Pool().Exec(context.Background(), sql, args...); err != nil {
		h.t.Fatal(err)
	}
}

// Activity on the sign-in page keeps a request alive, up to a hard cap.
func TestAuthRequestSlides(t *testing.T) {
	h := newHarness(t)
	s := h.newSite("site")
	id := h.pendingAuthRequest(s)

	h.execSQL(`UPDATE auth_requests SET expires_at = now() + interval '1 minute' WHERE id = $1`, id)
	resp := h.post("/accounts/v1/register/start?authRequestID="+id, map[string]string{"email": "slow@example.com"})
	resp.Body.Close()
	if _, exp := h.authRequestTimes(id); time.Until(exp) < store.AuthRequestTTL-time.Minute {
		t.Errorf("a step did not extend the request: expires in %v", time.Until(exp))
	}

	h.execSQL(`UPDATE auth_requests SET created_at = now() - $2::interval WHERE id = $1`,
		id, (store.AuthRequestMaxLife - 5*time.Minute).String())
	h.get("/signin?authRequestID=" + id).Body.Close()
	created, exp := h.authRequestTimes(id)
	if exp.After(created.Add(store.AuthRequestMaxLife).Add(time.Second)) {
		t.Errorf("extended past the cap: created %v, expires %v", created, exp)
	}
}

// A request that runs out while the person is still signing up sends them
// back to the site with login_required and the site's state, never to the
// account page.
func TestExpiredAuthRequestReturnsToTheSite(t *testing.T) {
	h := newHarness(t)
	s := h.newSite("site")
	id := h.pendingAuthRequest(s)
	h.execSQL(`UPDATE auth_requests SET expires_at = now() - interval '1 second' WHERE id = $1`, id)

	// Steps of an expired request do not bring it back.
	next := h.registerFor("late@example.com", "?authRequestID="+id)
	if want := "/login?authRequestID=" + id; next != want {
		t.Fatalf("after signing up, redirect = %q, want %q", next, want)
	}
	u, resp := h.follow(h.srv.URL+next, s.url)
	if u == nil {
		t.Fatalf("the handoff stopped at %s: %d %s", resp.Request.URL, resp.StatusCode, bodyString(t, resp))
	}
	if u.Query().Get("error") != "login_required" || u.Query().Get("state") != "st" || u.Query().Get("code") != "" {
		t.Errorf("sent to the site with %s", u.RawQuery)
	}

	// A page reloaded on the expired request goes the same way.
	u, resp = h.follow(h.srv.URL+"/signin?authRequestID="+id, s.url)
	if u == nil || u.Query().Get("error") != "login_required" {
		t.Errorf("reloading the sign-in page: %v %v", u, resp)
	}

	// Once the row is gone, the page says so.
	h.execSQL(`DELETE FROM auth_requests WHERE id = $1`, id)
	resp = h.get("/login?authRequestID=" + id)
	if body := bodyString(t, resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "expired") {
		t.Errorf("a forgotten request: %d", resp.StatusCode)
	}
}

// The whole invitation path: a site sends someone to sign up, the request runs
// out, and they still end up where the site meant them to go, signed in.
func TestSlowSignUpReachesTheSite(t *testing.T) {
	h := newHarness(t)
	s := h.newSite("site")
	resp, err := h.client.Get(s.url + "/auth/login?return_to=" + url.QueryEscape("/invite/abc"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	id := resp.Request.URL.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("not on the sign-in page: %s", resp.Request.URL)
	}
	h.execSQL(`UPDATE auth_requests SET expires_at = now() - interval '1 second' WHERE id = $1`, id)

	next := h.registerFor("invited@example.com", "?authRequestID="+id)
	resp, err = h.client.Get(h.srv.URL + next)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.HasPrefix(resp.Request.URL.String(), s.url+"/invite/abc") {
		t.Fatalf("ended at %s, want the invitation", resp.Request.URL)
	}
	if sess := h.siteSession(s); sess.Subject != h.subjectOf("invited@example.com") {
		t.Errorf("signed in to the site as %q", sess.Subject)
	}
}
