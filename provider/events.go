package provider

import (
	"context"
	"log/slog"
	"sync"
	"time"

	kitprotocol "github.com/Kolonnade/Portiko/protocol"

	"github.com/Kolonnade/Portiko/profile"
	"github.com/Kolonnade/Portiko/internal/store"
)

// notifyProfileChange pushes a profile change to every site that holds a live
// refresh token for the account, so an open page there shows the new name and
// avatar on its next focus check rather than after its next token refresh.
//
// The event is a Security Event Token (RFC 8417) shaped as the Shared Signals
// CAEP token-claims-change event, delivered by push (RFC 8935): a signed JWT
// POSTed to the site's registered events URI, server to server, so it reaches a
// site on another domain exactly as it reaches a subdomain. Delivery is best
// effort. A site that misses it catches up at its next token refresh, which
// carries the same claims and version.
func (h *Auth) notifyProfileChange(ctx context.Context, userID int64, subject, name, avatarKey string, version int64) {
	ctx, cancel := context.WithTimeout(ctx, logoutTimeout)
	defer cancel()

	ids, err := h.db.ActiveClientIDs(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "profile event: listing clients", "err", err)
		return
	}
	clients, err := h.db.EventRecipients(ctx, ids)
	if err != nil {
		slog.ErrorContext(ctx, "profile event: loading recipients", "err", err)
		return
	}

	avatar := ""
	if avatarKey != "" {
		avatar = profile.EmojiFor(avatarKey)
	}
	event := map[string]any{
		"event_timestamp": time.Now().Unix(),
		"claims": map[string]any{
			kitprotocol.ClaimName:      name,
			kitprotocol.ClaimAvatar:    avatar,
			kitprotocol.ClaimUpdatedAt: version,
		},
	}

	var wg sync.WaitGroup
	for _, c := range clients {
		wg.Add(1)
		go func(c store.Client) {
			defer wg.Done()
			log := slog.With("client_id", c.ClientID)
			token, err := h.ring.SignEvent(h.cfg.Issuer, c.ClientID, subject, kitprotocol.EventTokenClaimsChange, event)
			if err != nil {
				log.ErrorContext(ctx, "profile event: signing", "err", err)
				return
			}
			h.deliver(ctx, log, "profile event", c.EventsURI, "application/secevent+jwt", token)
		}(c)
	}
	wg.Wait()
}
