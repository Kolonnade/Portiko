package provider

import (
	"net/http"

	kitprotocol "github.com/Kolonnade/Portiko/protocol"
)

// Session: GET /accounts/v1/session[?account=n] — whether an account is signed
// in on this browser.
//
// Pages call it when they come back into view, because signing in and out
// usually happens in another tab and nothing else tells an open page. An
// account is named by its public sid, so a page can tell "signed in again" from
// "still signed in"; neither the cookie nor the subject is returned.
func (h *Auth) Session(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	list := h.accounts(r)
	a, ok := selectAccount(list, r.URL.Query().Get("account"))
	if !ok {
		writeError(w, http.StatusUnauthorized, &kitprotocol.Error{Code: kitprotocol.ErrLoginRequired})
		return
	}
	others := make([]map[string]any, 0, len(list))
	for _, x := range list {
		others = append(others, map[string]any{
			"account": x.Ordinal, "display_name": x.User.DisplayName, "avatar": x.User.Avatar, "default": x.IsDefault,
		})
	}
	writeJSON(w, map[string]any{
		"sid":          a.SID,
		"account":      a.Ordinal,
		"default":      a.IsDefault,
		"display_name": a.User.DisplayName,
		"avatar":       a.User.Avatar,
		"accounts":     others,
	})
}
