package provider

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Kolonnade/Portiko/internal/store"
)

// Login is the handoff between zitadel/oidc and the people signing in: the
// provider sends every authorization request here by id, and this decides
// whether an account already signed in can complete it, whether the person must
// choose, or whether a passkey ceremony is needed.
type Login struct{ auth *Auth }

// Start: GET /login?authRequestID=
func (l *Login) Start(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.URL.Query().Get("authRequestID")
	ar, err := l.auth.db.AuthRequestByID(ctx, id)
	if err != nil {
		l.auth.pages.message(w, http.StatusBadRequest, "This sign-in link has expired",
			"Go back to the site you were signing in to and try again.")
		return
	}
	c, err := l.auth.db.ClientByID(ctx, ar.ClientID)
	if err != nil {
		l.fail(w, r, ar, oidc.ErrInvalidRequest().WithDescription("unknown client"))
		return
	}
	// There is no consent screen yet, so only this deployment's own sites may be
	// signed in to. A third party must not be able to borrow the sign-in.
	if !c.FirstParty() {
		l.fail(w, r, ar, oidc.ErrAccessDenied().WithDescription("consent is not yet supported, so only first-party sites may sign in"))
		return
	}

	signedIn := l.auth.accounts(r)
	candidates := l.candidates(r, ar, signedIn)
	prompt := func(p string) bool { return slices.Contains(ar.Prompt, p) }

	switch {
	case prompt(oidc.PromptNone):
		switch len(candidates) {
		case 1:
			l.complete(w, r, ar, &candidates[0])
		case 0:
			l.fail(w, r, ar, oidc.ErrLoginRequired().WithDescription("no signed-in account matches this request"))
		default:
			// OpenID Connect names this account_selection_required, a kind of
			// interaction_required: the person has to choose, and a silent
			// request cannot ask them.
			l.fail(w, r, ar, oidc.ErrInteractionRequired().WithDescription("account_selection_required: several accounts are signed in"))
		}
	case prompt(oidc.PromptLogin):
		http.Redirect(w, r, "/signin?authRequestID="+url.QueryEscape(id), http.StatusFound)
	case prompt(oidc.PromptSelectAccount) || len(candidates) > 1:
		l.auth.pages.chooser(w, r, chooserData{
			AuthRequestID: id, ClientName: c.DisplayName, Accounts: viewsOf(candidates, -1),
		})
	case len(candidates) == 1:
		l.complete(w, r, ar, &candidates[0])
	default:
		http.Redirect(w, r, "/signin?authRequestID="+url.QueryEscape(id), http.StatusFound)
	}
}

// Select: POST /login/select — the chooser's form.
func (l *Login) Select(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r, l.auth.cfg.Issuer) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	id := r.PostFormValue("authRequestID")
	ar, err := l.auth.db.AuthRequestByID(ctx, id)
	if err != nil {
		l.auth.pages.message(w, http.StatusBadRequest, "This sign-in link has expired",
			"Go back to the site you were signing in to and try again.")
		return
	}
	n, err := strconv.Atoi(r.PostFormValue("account"))
	if err != nil {
		http.Redirect(w, r, "/login?authRequestID="+url.QueryEscape(id), http.StatusSeeOther)
		return
	}
	chosen := findAccount(l.candidates(r, ar, l.auth.accounts(r)), n)
	if chosen == nil {
		// Signed out in another tab, or not an account this request allows:
		// ask again rather than guess.
		http.Redirect(w, r, "/login?authRequestID="+url.QueryEscape(id), http.StatusSeeOther)
		return
	}
	l.complete(w, r, ar, chosen)
}

// candidates narrows the signed-in accounts to those the request allows: the
// subject named by an id_token_hint, the account named by a login_hint, and only
// sessions whose authentication is recent enough for max_age.
func (l *Login) candidates(r *http.Request, ar *store.AuthRequest, signedIn []account) []account {
	var hintUser int64
	if ar.LoginHint != "" {
		if u, err := l.auth.db.BySubject(r.Context(), ar.LoginHint); err == nil {
			hintUser = u.ID
		} else if u, err := l.auth.db.ByIdentifier(r.Context(), "email", ar.LoginHint); err == nil {
			hintUser = u.ID
		}
	}
	out := make([]account, 0, len(signedIn))
	for _, a := range signedIn {
		if ar.HintSubject != "" && a.User.Subject != ar.HintSubject {
			continue
		}
		if ar.LoginHint != "" && hintUser != 0 && a.UserID != hintUser {
			continue
		}
		if ar.MaxAge != nil && time.Since(a.AuthenticatedAt) > time.Duration(*ar.MaxAge)*time.Second {
			continue
		}
		out = append(out, a)
	}
	return out
}

// complete records which account completes the request and resumes it inside
// zitadel/oidc, which issues the code.
func (l *Login) complete(w http.ResponseWriter, r *http.Request, ar *store.AuthRequest, a *account) {
	if err := l.auth.db.CompleteAuthRequest(r.Context(), ar.ID, a.UserID, a.SID, a.AuthenticatedAt, a.AMR); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			l.auth.pages.message(w, http.StatusBadRequest, "This sign-in link has expired",
				"Go back to the site you were signing in to and try again.")
			return
		}
		slog.ErrorContext(r.Context(), "completing authorization request", "err", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, callbackURL(l.auth.cfg.Issuer, ar.ID), http.StatusFound)
}

// fail sends a protocol error back to the client's registered redirect URI.
func (l *Login) fail(w http.ResponseWriter, r *http.Request, ar *store.AuthRequest, err error) {
	op.AuthRequestError(w, r, errAuthRequest{ar}, err, l.auth.op)
}

// sameOrigin reports whether a state-changing request came from this provider's
// own pages. The cookie is SameSite=Lax already; this is the second lock.
func sameOrigin(r *http.Request, issuer string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Older browsers omit Origin on same-origin form posts; fall back to
		// Referer, and refuse when neither is present.
		ref, err := url.Parse(r.Header.Get("Referer"))
		if err != nil || ref.Host == "" {
			return false
		}
		origin = ref.Scheme + "://" + ref.Host
	}
	iss, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	return origin == iss.Scheme+"://"+iss.Host
}
