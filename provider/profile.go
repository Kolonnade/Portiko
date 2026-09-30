package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/Kolonnade/Portiko/internal/store"
	"github.com/Kolonnade/Portiko/profile"
	kitprotocol "github.com/Kolonnade/Portiko/protocol"
)

// builtinProfiles is the default presentation: the display name and emoji
// avatar an account holder chooses on the profile page.
type builtinProfiles struct{ db *store.DB }

func (b builtinProfiles) Presentation(ctx context.Context, subject string) (profile.Presentation, error) {
	u, err := b.db.BySubject(ctx, subject)
	if err != nil {
		return profile.Presentation{}, err
	}
	p := profile.Presentation{Name: u.DisplayName, UpdatedAt: u.ProfileUpdatedAt}
	if u.Avatar != "" {
		p.Avatar = profile.EmojiFor(u.Avatar)
	}
	return p, nil
}

// passkeySignal is what a page hands to PublicKeyCredential.signalCurrentUserDetails
// so the passkey provider (iCloud Keychain, Google Password Manager, …) renames
// the saved passkey. Without it a passkey keeps the name it was created with.
type passkeySignal struct {
	RPID    string   `json:"rp_id"`
	UserIDs []string `json:"user_ids"`
	Name    string   `json:"name"`
}

func (h *Auth) signalFor(ctx context.Context, userID int64, name string) *passkeySignal {
	handles, err := h.db.UserHandles(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "profile: loading user handles", "err", err)
		return nil
	}
	s := &passkeySignal{RPID: h.cfg.WebAuthnRPID, Name: name, UserIDs: []string{}}
	for _, hd := range handles {
		s.UserIDs = append(s.UserIDs, base64.RawURLEncoding.EncodeToString(hd))
	}
	return s
}

// UpdateProfile: POST /accounts/v1/profile {"account", "display_name", "avatar"}
//
// Requiring a JSON content type means a cross-site page cannot post here without
// a CORS preflight, and the cookie is SameSite=Lax besides. The account is named
// explicitly: with several signed in, the server never guesses which one a
// request means.
func (h *Auth) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, &kitprotocol.Error{
			Code: kitprotocol.ErrInvalidRequest, Description: "expected application/json"})
		return
	}
	var body struct {
		Account     *int   `json:"account"`
		DisplayName string `json:"display_name"`
		Avatar      string `json:"avatar"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, &kitprotocol.Error{
			Code: kitprotocol.ErrInvalidRequest, Description: "malformed request body"})
		return
	}
	raw := ""
	if body.Account != nil {
		raw = strconv.Itoa(*body.Account)
	}
	a, ok := selectAccount(h.accounts(r), raw)
	if !ok {
		writeError(w, http.StatusUnauthorized, &kitprotocol.Error{Code: kitprotocol.ErrLoginRequired})
		return
	}
	name, err := profile.NormalizeName(body.DisplayName)
	if err != nil {
		writeError(w, http.StatusBadRequest, &kitprotocol.Error{
			Code: kitprotocol.ErrInvalidRequest, Description: err.Error()})
		return
	}
	if !profile.ValidAvatar(body.Avatar) {
		writeError(w, http.StatusBadRequest, &kitprotocol.Error{
			Code: kitprotocol.ErrInvalidRequest, Description: profile.ErrAvatarUnknown.Error()})
		return
	}
	version, err := h.db.UpdateProfile(r.Context(), a.UserID, name, body.Avatar)
	if err != nil {
		slog.ErrorContext(r.Context(), "profile: saving", "err", err)
		writeError(w, http.StatusInternalServerError, &kitprotocol.Error{Code: kitprotocol.ErrServerError})
		return
	}
	// Tell the sites now rather than at their next token refresh, in the
	// background: saving shouldn't wait on a slow or unreachable site.
	go h.notifyProfileChange(context.WithoutCancel(r.Context()), a.UserID, a.User.Subject, name, body.Avatar, version)

	writeJSON(w, map[string]any{
		"account":         a.Ordinal,
		"display_name":    name,
		"avatar":          body.Avatar,
		"emoji":           profile.EmojiFor(body.Avatar),
		"profile_version": version,
	})
}
