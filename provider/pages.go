package provider

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Kolonnade/Portiko/internal/config"
	"github.com/Kolonnade/Portiko/profile"
)

//go:embed templates/*.html
var builtinTemplates embed.FS

// Pages serves the provider's own pages.
type Pages struct {
	cfg  *config.Config
	tmpl *template.Template
	auth *Auth
}

// NewPages loads the templates, preferring an operator's override directory, so
// a second deployment can be rebranded without a fork.
func NewPages(cfg *config.Config, auth *Auth) (*Pages, error) {
	var (
		tmpl *template.Template
		err  error
	)
	if cfg.TemplateDir != "" {
		tmpl, err = template.ParseGlob(filepath.Join(cfg.TemplateDir, "*.html"))
	} else {
		tmpl, err = template.ParseFS(builtinTemplates, "templates/*.html")
	}
	if err != nil {
		return nil, err
	}
	p := &Pages{cfg: cfg, tmpl: tmpl, auth: auth}
	auth.pages = p
	return p, nil
}

// render writes a page that must never be cached: every one of them is either
// per-account or part of a sign-in.
func (p *Pages) render(w http.ResponseWriter, status int, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := p.tmpl.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("rendering page", "template", name, "err", err)
	}
}

// accountView is how an account appears in a switcher or chooser.
type accountView struct {
	Ordinal int
	Name    string
	Emoji   string
	Default bool
	Current bool
}

func viewsOf(list []account, current int) []accountView {
	out := make([]accountView, 0, len(list))
	for _, a := range list {
		out = append(out, accountView{
			Ordinal: a.Ordinal, Name: a.User.DisplayName, Emoji: profile.EmojiFor(a.User.Avatar),
			Default: a.IsDefault, Current: a.Ordinal == current,
		})
	}
	return out
}

// Root: GET / — the default account's home.
func (p *Pages) Root(w http.ResponseWriter, r *http.Request) {
	a := defaultAccount(p.auth.accounts(r))
	if a == nil {
		http.Redirect(w, r, "/signin", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/u/"+strconv.Itoa(a.Ordinal)+"/", http.StatusFound)
}

// ProfileRedirect: GET /profile — sites link here without knowing numbers.
func (p *Pages) ProfileRedirect(w http.ResponseWriter, r *http.Request) {
	a := defaultAccount(p.auth.accounts(r))
	if a == nil {
		http.Redirect(w, r, "/signin?return_to=/profile", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/u/"+strconv.Itoa(a.Ordinal)+"/profile", http.StatusFound)
}

// site is one first-party site linked from the home page.
type site struct{ Name, URL, Host string }

// Home: GET /u/{n}/ — one account's page, with every account in this browser in
// the switcher.
func (p *Pages) Home(w http.ResponseWriter, r *http.Request) {
	list := p.auth.accounts(r)
	a, ok := selectAccount(list, r.PathValue("n"))
	if !ok {
		p.stale(w, r, list)
		return
	}
	var sites []site
	clients, err := p.auth.db.FirstPartyClients(r.Context())
	if err != nil {
		slog.Error("home: listing first-party clients", "err", err)
	}
	for _, c := range clients {
		au, err := url.Parse(c.Audience)
		if err != nil || (au.Scheme != "https" && au.Scheme != "http") || au.Host == "" {
			continue
		}
		name := c.DisplayName
		if name == "" {
			name = c.ClientID
		}
		sites = append(sites, site{Name: name, URL: au.Scheme + "://" + au.Host + "/", Host: au.Host})
	}
	var signal *passkeySignal
	if a.User.DisplayName != "" {
		signal = p.auth.signalFor(r.Context(), a.UserID, a.User.DisplayName)
	}
	p.render(w, http.StatusOK, "home.html", map[string]any{
		"ServiceName": p.cfg.ServiceName,
		"Account":     a.Ordinal,
		"IsDefault":   a.IsDefault,
		"Name":        a.User.DisplayName,
		"Emoji":       profile.EmojiFor(a.User.Avatar),
		"AvatarKey":   a.User.Avatar,
		"SID":         a.SID,
		"Accounts":    viewsOf(list, a.Ordinal),
		"CanAdd":      len(list) < maxAccounts,
		"Sites":       sites,
		"Signal":      signal,
		// The profile version gates the passkey rename signal to once per change.
		"ProfileVersion": a.User.ProfileUpdatedAt,
	})
}

// Profile: GET /u/{n}/profile
func (p *Pages) Profile(w http.ResponseWriter, r *http.Request) {
	list := p.auth.accounts(r)
	a, ok := selectAccount(list, r.PathValue("n"))
	if !ok {
		p.stale(w, r, list)
		return
	}
	p.render(w, http.StatusOK, "profile.html", map[string]any{
		"ServiceName": p.cfg.ServiceName,
		"Account":     a.Ordinal,
		"SID":         a.SID,
		"DisplayName": a.User.DisplayName,
		"Avatar":      a.User.Avatar,
		"Avatars":     profile.Avatars,
		"MaxNameLen":  profile.MaxNameLen,
		"Signal":      p.auth.signalFor(r.Context(), a.UserID, a.User.DisplayName),
	})
}

// SignIn: GET /signin[?authRequestID=][&return_to=][&add=1]
func (p *Pages) SignIn(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// return_to is only ever a local path. Echoing an absolute URL would make
	// the sign-in page an open redirect.
	returnTo := q.Get("return_to")
	if !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") {
		returnTo = ""
	}
	id := q.Get("authRequestID")
	list := p.auth.accounts(r)
	adding := q.Get("add") == "1"
	if len(list) > 0 && id == "" && !adding {
		to := returnTo
		if to == "" {
			to = "/"
		}
		http.Redirect(w, r, to, http.StatusFound)
		return
	}
	p.render(w, http.StatusOK, "signin.html", map[string]any{
		"ServiceName":   p.cfg.ServiceName,
		"ReturnTo":      returnTo,
		"AuthRequestID": id,
		"Adding":        len(list) > 0,
	})
}

type chooserData struct {
	AuthRequestID string
	ClientName    string
	Accounts      []accountView
}

// chooser asks which signed-in account should sign in to a site.
func (p *Pages) chooser(w http.ResponseWriter, _ *http.Request, d chooserData) {
	p.render(w, http.StatusOK, "chooser.html", map[string]any{
		"ServiceName":   p.cfg.ServiceName,
		"Mode":          "choose",
		"AuthRequestID": d.AuthRequestID,
		"ClientName":    d.ClientName,
		"Accounts":      d.Accounts,
	})
}

// stale answers a page for an account number this browser does not hold. It
// lists the accounts that are signed in and never shows one of them in its
// place, because a stale link must not open somebody else's account.
func (p *Pages) stale(w http.ResponseWriter, _ *http.Request, list []account) {
	if len(list) == 0 {
		p.render(w, http.StatusNotFound, "chooser.html", map[string]any{
			"ServiceName": p.cfg.ServiceName, "Mode": "stale",
		})
		return
	}
	p.render(w, http.StatusNotFound, "chooser.html", map[string]any{
		"ServiceName": p.cfg.ServiceName, "Mode": "stale", "Accounts": viewsOf(list, -1),
	})
}

// message renders a plain explanation.
func (p *Pages) message(w http.ResponseWriter, status int, title, body string) {
	p.render(w, status, "chooser.html", map[string]any{
		"ServiceName": p.cfg.ServiceName, "Mode": "message", "Title": title, "Body": body,
	})
}
