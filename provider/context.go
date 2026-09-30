package provider

import (
	"context"

	"github.com/Kolonnade/Portiko/protocol"
)

func contextWithVersion(ctx context.Context, v protocol.Version) context.Context {
	return context.WithValue(ctx, versionKey{}, v)
}
