package provider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/Kolonnade/Portiko/internal/store"
)

// SignInStage names one step of the sign-in page's funnel. docs/sign-in-events.md
// lists every stage and when it fires.
type SignInStage string

// The stages, in the order a person meets them.
const (
	StagePageShown            SignInStage = "page_shown"
	StageEmailSubmitted       SignInStage = "email_submitted"
	StageCodeSent             SignInStage = "code_sent"
	StageCodeVerified         SignInStage = "code_verified"
	StagePasskeyCreateStarted SignInStage = "passkey_create_started"
	StagePasskeyCreateDone    SignInStage = "passkey_create_finished"
	StagePasskeySignInStarted SignInStage = "passkey_signin_started"
	StagePasskeySignInDone    SignInStage = "passkey_signin_finished"
	StageRedirected           SignInStage = "redirected"
)

// SignInOutcome says how a stage ended.
type SignInOutcome string

const (
	// OutcomeOK: the stage succeeded.
	OutcomeOK SignInOutcome = "ok"
	// OutcomeFail: the stage failed; Reason says why.
	OutcomeFail SignInOutcome = "fail"
	// OutcomeAbandon: the person dismissed the browser's passkey dialog.
	OutcomeAbandon SignInOutcome = "abandon"
)

// SignInEvent is one stage of one sign-in attempt. It never carries an email
// address, an IP address or a user ID.
type SignInEvent struct {
	// FlowID ties the stages of one attempt together: the authorization request
	// ID when a site sent the person, otherwise a random ID minted per page view.
	FlowID string
	// ClientID is the site being signed in to, when there is one.
	ClientID  string
	Stage     SignInStage
	Outcome   SignInOutcome
	Reason    string
	UserAgent string
	// Source is "server" for stages the provider observed itself, "browser" for
	// those the sign-in page reported.
	Source string
	Time   time.Time
}

// signInEvents bounds the sign-in page's own reports. A page reports at most a
// couple of failures per attempt; this is the flood ceiling.
var signInEvents = limit{perIP: 120, window: time.Hour}

var flowPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

var browserErrorPattern = regexp.MustCompile(`^[A-Za-z]{1,40}$`)

// newFlowID mints a random per-page flow ID.
func newFlowID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// flowOf reads the flow from the request's query: the authorization request ID,
// else a well-formed flow parameter.
func flowOf(r *http.Request) (flow, authRequestID string) {
	q := r.URL.Query()
	if id := q.Get("authRequestID"); id != "" {
		return id, id
	}
	if f := q.Get("flow"); flowPattern.MatchString(f) {
		return f, ""
	}
	return "", ""
}

// clientFor looks up the site an authorization request belongs to, or "".
func (h *Auth) clientFor(ctx context.Context, authRequestID string) string {
	if authRequestID == "" {
		return ""
	}
	ar, err := h.db.AuthRequestByID(ctx, authRequestID)
	if err != nil {
		return ""
	}
	return ar.ClientID
}

// emit reports a stage the server observed, taking the flow from the query.
func (h *Auth) emit(r *http.Request, stage SignInStage, outcome SignInOutcome, reason string) {
	if h.onEvent == nil {
		return
	}
	flow, id := flowOf(r)
	h.emitFor(r, flow, h.clientFor(r.Context(), id), stage, outcome, reason, "server")
}

// emitFor reports a stage with the flow and client given. The hook runs on the
// request goroutine; a panic in it is logged, never served.
func (h *Auth) emitFor(r *http.Request, flow, clientID string, stage SignInStage, outcome SignInOutcome, reason, source string) {
	if h.onEvent == nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			slog.Error("sign-in event hook panicked", "stage", string(stage), "panic", p)
		}
	}()
	h.onEvent(r.Context(), SignInEvent{
		FlowID: flow, ClientID: clientID, Stage: stage, Outcome: outcome, Reason: reason,
		UserAgent: r.UserAgent(), Source: source, Time: time.Now(),
	})
}

// limitedEvent reports a rate-limited request as a failure of the stage the
// endpoint serves.
func (h *Auth) limitedEvent(r *http.Request, endpoint string) {
	var stage SignInStage
	switch endpoint {
	case "register.start":
		stage = StageCodeSent
	case "register.verify":
		stage = StageCodeVerified
	case "login.start":
		stage = StagePasskeySignInStarted
	case "login.finish":
		stage = StagePasskeySignInDone
	default:
		return
	}
	h.emit(r, stage, OutcomeFail, "rate_limited")
}

// storeReason names why a code was not accepted. It reaches only the hook; the
// client always sees the same generic failure.
func storeReason(err error) string {
	switch {
	case errors.Is(err, store.ErrBadCode):
		return "code_wrong"
	case errors.Is(err, store.ErrExpired):
		return "code_expired"
	case errors.Is(err, store.ErrTooManyAttempts):
		return "too_many_attempts"
	case errors.Is(err, store.ErrNotFound):
		return "code_unknown"
	default:
		return "code_rejected"
	}
}

// SignInEvent: POST /signin/event[?authRequestID=|?flow=] {"stage","error"}
//
// The sign-in page reports a passkey dialog that failed or was dismissed, which
// the server cannot see. Always 204: the page never waits on or learns from it.
func (h *Auth) SignInEvent(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r, h.cfg.Issuer) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	defer w.WriteHeader(http.StatusNoContent)
	if h.onEvent == nil {
		return
	}
	var body struct {
		Stage string `json:"stage"`
		Error string `json:"error"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body) != nil {
		return
	}
	stage := SignInStage(body.Stage)
	if stage != StagePasskeyCreateDone && stage != StagePasskeySignInDone {
		return
	}
	reason := body.Error
	if !browserErrorPattern.MatchString(reason) {
		reason = "UnknownError"
	}
	outcome := OutcomeFail
	if reason == "NotAllowedError" || reason == "AbortError" {
		outcome = OutcomeAbandon
	}
	flow, id := flowOf(r)
	h.emitFor(r, flow, h.clientFor(r.Context(), id), stage, outcome, reason, "browser")
}
