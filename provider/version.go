// Package handlers holds the HTTP surface: discovery, the passkey ceremonies,
// and the OAuth endpoints.
package provider

import (
	"encoding/json"
	"net/http"

	"github.com/Kolonnade/Portiko/protocol"
)

// Supported is the set of protocol versions this build serves. A new minor is
// appended here; a new major is served at its own path prefix alongside the old.
var Supported = []protocol.Version{protocol.V1_0}

// Preferred is the version advertised as best.
var Preferred = protocol.V1_0

// Minimum is what a client is assumed to speak when it sends no version header.
var Minimum = protocol.V1_0

type versionKey struct{}

// NegotiatedVersion returns the version chosen for this request.
func NegotiatedVersion(r *http.Request) protocol.Version {
	if v, ok := r.Context().Value(versionKey{}).(protocol.Version); ok {
		return v
	}
	return Minimum
}

// VersionMiddleware negotiates the protocol version for every request.
//
// A client that asks for a major we do not serve gets a 400 naming what we do
// serve — not a 404, which would look like a routing mistake and send the reader
// looking in the wrong place.
func VersionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested := Minimum
		deprecated := true // no header means an assumed version, which we flag

		if raw := r.Header.Get(protocol.HeaderVersion); raw != "" {
			parsed, err := protocol.ParseVersion(raw)
			if err != nil {
				writeError(w, http.StatusBadRequest, &protocol.Error{
					Code:        protocol.ErrUnsupportedProtocol,
					Description: err.Error(),
					Supported:   versionStrings(),
				})
				return
			}
			requested, deprecated = parsed, false
		}

		negotiated, err := protocol.Negotiate(requested, Supported)
		if err != nil {
			writeError(w, http.StatusBadRequest, &protocol.Error{
				Code:        protocol.ErrUnsupportedProtocol,
				Description: err.Error(),
				Supported:   versionStrings(),
			})
			return
		}

		w.Header().Set(protocol.HeaderVersion, negotiated.String())
		if deprecated {
			// RFC 8594. Tells a client relying on the default that it should
			// start being explicit, before the default changes under it.
			w.Header().Set("Deprecation", "true")
		}

		ctx := contextWithVersion(r.Context(), negotiated)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func versionStrings() []string {
	out := make([]string, len(Supported))
	for i, v := range Supported {
		out[i] = v.String()
	}
	return out
}

func writeError(w http.ResponseWriter, status int, e *protocol.Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(e)
}
