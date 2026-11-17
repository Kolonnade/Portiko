package provider_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/descope/virtualwebauthn"

	"github.com/Kolonnade/Portiko/provider"
)

// eventLog records what the sign-in event hook was given.
type eventLog struct {
	mu     sync.Mutex
	events []provider.SignInEvent
}

func (l *eventLog) add(_ context.Context, e provider.SignInEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *eventLog) all() []provider.SignInEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]provider.SignInEvent(nil), l.events...)
}

// find returns the first event of a stage with the given outcome, or nil.
func (l *eventLog) find(stage provider.SignInStage, outcome provider.SignInOutcome) *provider.SignInEvent {
	for _, e := range l.all() {
		if e.Stage == stage && e.Outcome == outcome {
			return &e
		}
	}
	return nil
}

// withEvents restarts the provider against the same database with a sign-in
// event hook, and returns what it records.
func (h *harness) withEvents() *eventLog {
	h.t.Helper()
	log := &eventLog{}
	cfg, err := provider.LoadConfig()
	if err != nil {
		h.t.Fatalf("events: config: %v", err)
	}
	p, err := provider.New(context.Background(), cfg, provider.Options{Mailer: h.mail, OnSignInEvent: log.add})
	if err != nil {
		h.t.Fatalf("events: provider: %v", err)
	}
	h.t.Cleanup(p.Close)
	h.handler.Store(p.Handler())
	h.p, h.db, h.cfg = p, p.DB(), cfg
	return log
}

// registerInFlow is register with every ceremony request carrying ?flow=.
func (h *harness) registerInFlow(email, flow string) {
	h.t.Helper()
	q := "?flow=" + flow
	start := map[string]string{"email": email, "bootstrap_code": h.cfg.BootstrapCode}
	if resp := h.post("/accounts/v1/register/start"+q, start); resp.StatusCode != http.StatusAccepted {
		h.t.Fatalf("register/start: %s", bodyString(h.t, resp))
	}
	resp := h.post("/accounts/v1/register/verify"+q, map[string]string{"email": email, "code": h.latestCode(email)})
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
	fin, err := h.client.Post(h.srv.URL+h.prefix+"/accounts/v1/register/finish"+q, "application/json", strings.NewReader(attestation))
	if err != nil {
		h.t.Fatalf("register/finish: %v", err)
	}
	if fin.StatusCode != http.StatusOK {
		h.t.Fatalf("register/finish: %d %s", fin.StatusCode, bodyString(h.t, fin))
	}
	fin.Body.Close()
	h.auth.AddCredential(credential)
}

// loginInFlow is login with both ceremony requests carrying ?flow=.
func (h *harness) loginInFlow(flow string) {
	h.t.Helper()
	q := "?flow=" + flow
	resp := h.get("/accounts/v1/login/start" + q)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	options, err := virtualwebauthn.ParseAssertionOptions(string(raw))
	if err != nil {
		h.t.Fatalf("parsing assertion options: %v", err)
	}
	credential := h.auth.FindAllowedCredential(*options)
	if credential == nil {
		credential = &h.auth.Credentials[0]
	}
	assertion := virtualwebauthn.CreateAssertionResponse(h.rp, h.auth, *credential, *options)
	fin, err := h.client.Post(h.srv.URL+h.prefix+"/accounts/v1/login/finish"+q, "application/json", strings.NewReader(assertion))
	if err != nil {
		h.t.Fatalf("login/finish: %v", err)
	}
	if fin.StatusCode != http.StatusOK {
		h.t.Fatalf("login/finish: %d %s", fin.StatusCode, bodyString(h.t, fin))
	}
	fin.Body.Close()
}

// reportEvent posts what the sign-in page sends when a passkey dialog fails.
func (h *harness) reportEvent(query, origin string, body any) int {
	h.t.Helper()
	blob, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+h.prefix+"/signin/event"+query, bytes.NewReader(blob))
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestSignInEventsTraceRegistrationAndLogin(t *testing.T) {
	h := newHarness(t)
	log := h.withEvents()
	const email = "trace@example.com"

	page := bodyString(t, h.get("/signin"))
	shown := log.find(provider.StagePageShown, provider.OutcomeOK)
	if shown == nil || shown.FlowID == "" {
		t.Fatalf("no page_shown event with a flow: %+v", log.all())
	}
	if !strings.Contains(page, shown.FlowID) {
		t.Error("the page does not carry the flow ID its event named")
	}
	if !regexp.MustCompile(`const EVENTS =\s*true\s*;`).MatchString(page) {
		t.Error("the page does not know events are on")
	}

	h.registerInFlow(email, "f1")
	h.loginInFlow("f1")

	want := []provider.SignInStage{
		provider.StageEmailSubmitted, provider.StageCodeSent, provider.StageCodeVerified,
		provider.StagePasskeyCreateStarted, provider.StagePasskeyCreateDone,
		provider.StagePasskeySignInStarted, provider.StagePasskeySignInDone,
	}
	for _, stage := range want {
		e := log.find(stage, provider.OutcomeOK)
		if e == nil {
			t.Errorf("no ok event for %s: %+v", stage, log.all())
			continue
		}
		if e.FlowID != "f1" || e.UserAgent == "" || e.Source != "server" || e.Time.IsZero() {
			t.Errorf("%s: %+v", stage, *e)
		}
	}
	for _, e := range log.all() {
		if e.Outcome != provider.OutcomeOK {
			t.Errorf("unexpected failure: %+v", e)
		}
		if blob, _ := json.Marshal(e); strings.Contains(string(blob), "trace@") {
			t.Errorf("an event carries the email: %s", blob)
		}
	}
}

func TestSignInEventWrongCodeNamesReason(t *testing.T) {
	h := newHarness(t)
	log := h.withEvents()
	const email = "wrong@example.com"
	start := map[string]string{"email": email, "bootstrap_code": h.cfg.BootstrapCode}
	if resp := h.post("/accounts/v1/register/start?flow=f3", start); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("register/start: %s", bodyString(t, resp))
	}
	code := h.latestCode(email)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	resp := h.post("/accounts/v1/register/verify?flow=f3", map[string]string{"email": email, "code": wrong})
	if body := bodyString(t, resp); resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "authentication_failed") {
		t.Fatalf("wrong code answered %d %s", resp.StatusCode, body)
	}
	e := log.find(provider.StageCodeVerified, provider.OutcomeFail)
	if e == nil || e.Reason != "code_wrong" || e.FlowID != "f3" {
		t.Fatalf("code_verified fail: %+v", log.all())
	}
}

func TestSignInEventsCarryClientAndRedirect(t *testing.T) {
	h := newHarness(t)
	h.register("client@example.com")
	log := h.withEvents()
	s := h.newSite("groups")

	resp, err := h.client.Get(s.url + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	e := log.find(provider.StageRedirected, provider.OutcomeOK)
	if e == nil {
		t.Fatalf("no redirected event: %+v", log.all())
	}
	if e.ClientID != s.clientID || e.FlowID == "" {
		t.Errorf("redirected: %+v", *e)
	}
}

func TestBrowserReportedEvent(t *testing.T) {
	h := newHarness(t)
	log := h.withEvents()

	if code := h.reportEvent("?flow=f2", h.srv.URL, map[string]string{"stage": "passkey_create_finished", "error": "NotAllowedError"}); code != http.StatusNoContent {
		t.Fatalf("report: %d", code)
	}
	e := log.find(provider.StagePasskeyCreateDone, provider.OutcomeAbandon)
	if e == nil || e.Source != "browser" || e.FlowID != "f2" || e.Reason != "NotAllowedError" {
		t.Fatalf("abandon: %+v", log.all())
	}

	h.reportEvent("?flow=f2", h.srv.URL, map[string]string{"stage": "passkey_signin_finished", "error": "InvalidStateError"})
	if e := log.find(provider.StagePasskeySignInDone, provider.OutcomeFail); e == nil || e.Reason != "InvalidStateError" {
		t.Fatalf("fail: %+v", log.all())
	}

	h.reportEvent("?authRequestID=someone%40example.com", h.srv.URL, map[string]string{"stage": "passkey_signin_finished", "error": "AbortError"})
	if e := log.find(provider.StagePasskeySignInDone, provider.OutcomeAbandon); e == nil || e.FlowID != "" {
		t.Fatalf("malformed authRequestID became a flow: %+v", log.all())
	}

	n := len(log.all())
	if code := h.reportEvent("?flow=f2", h.srv.URL, map[string]string{"stage": "code_verified", "error": "X"}); code != http.StatusNoContent {
		t.Errorf("bad stage: %d", code)
	}
	if code := h.reportEvent("?flow=f2", "", map[string]string{"stage": "passkey_create_finished", "error": "X"}); code != http.StatusForbidden {
		t.Errorf("no origin: %d", code)
	}
	if code := h.reportEvent("?flow=f2", "http://elsewhere.example", map[string]string{"stage": "passkey_create_finished", "error": "X"}); code != http.StatusForbidden {
		t.Errorf("foreign origin: %d", code)
	}
	if got := len(log.all()); got != n {
		t.Errorf("refused reports were recorded: %+v", log.all()[n:])
	}
}

func TestSignInEventsOffByDefault(t *testing.T) {
	h := newHarness(t)
	if code := h.reportEvent("?flow=f4", h.srv.URL, map[string]string{"stage": "passkey_create_finished", "error": "NotAllowedError"}); code != http.StatusNoContent {
		t.Errorf("report with no hook: %d", code)
	}
	if page := bodyString(t, h.get("/signin")); !regexp.MustCompile(`const EVENTS =\s*false\s*;`).MatchString(page) {
		t.Error("the page thinks events are on")
	}
}
