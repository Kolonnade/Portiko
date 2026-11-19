# Site sessions that survive a restart

A site signed in through the `rp` package keeps each signed-in browser as a
server-side `session.Session`: the tokens, the person's name, avatar and email,
and the provider's `sid`. The browser holds only an opaque id in the
`accounts_rp_session` cookie.

`session.NewMemoryStore()` keeps those sessions in the process. Every deploy or
restart signs everyone out, and two replicas do not share sessions. Use it for
tests and local development only.

`rp/session/pgstore` keeps them in PostgreSQL.

## Using it

```go
import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Kolonnade/Portiko/rp"
	"github.com/Kolonnade/Portiko/rp/session/pgstore"
)

pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
// ...
key, err := hex.DecodeString(os.Getenv("SESSION_KEY")) // 32 bytes: openssl rand -hex 32
// ...
sessions, err := pgstore.New(pgstore.Config{Pool: pool, Key: key})
if err != nil { ... }
if err := sessions.Migrate(ctx); err != nil { ... } // creates the table; safe on every start
go sessions.RunPruner(ctx, time.Hour)               // deletes expired rows

client, err := rp.New(ctx, rp.Config{ /* ... */ Sessions: sessions})
```

The environment variable names are the site's choice; the package reads no
environment itself.

| Config | |
|---|---|
| `Pool` | The site's database. Required. |
| `Key` | Exactly 32 random bytes that seal the session contents. Required. The same on every replica and stable across restarts, or every session stops opening and everyone is signed out. Keep it with the site's other secrets. |
| `OldKeys` | Earlier keys, tried when `Key` does not open a row. See rotation below. |
| `Table` | The table, optionally schema-qualified (`app.sessions`). Defaults to `portiko_rp_sessions`. Lowercase letters, digits and `_` only. |

The store implements `session.LogoutStore` and `session.ProfileStore`, so
back-channel logout and pushed profile changes work as they do with the memory
store.

## What is stored

| Column | Contents |
|---|---|
| `id_hash` | SHA-256 of the session id. The cookie value itself is never stored, so a copy of the table cannot be replayed as cookies. |
| `subject`, `sid` | The provider's opaque subject and SSO session id, in the clear because logout queries on them. |
| `profile_version` | So pushed profile updates arriving out of order never regress a session. |
| `sealed` | AES-256-GCM of the access, refresh and ID tokens, the email, name, avatar and access-token expiry, with the row's `id_hash` as associated data, so a sealed value copied to another row does not open there. |
| `expires_at`, `updated_at` | Expiry and last write. |

A row that no configured key opens reads as signed out (`session.ErrNotFound`),
not as an error, and is logged once per read.

## Pruning

`Get` never returns an expired session. Expired rows stay in the table until
`Prune` deletes them; `RunPruner(ctx, every)` calls it on a ticker until `ctx`
ends. Running it on several replicas at once is harmless. A site with its own
scheduler can call `Prune` instead.

## Rotating the key

1. Deploy with the new key as `Key` and the old one in `OldKeys`.
2. Rows are resealed under the new key the next time they are written (sign-in,
   token refresh, profile change). Rows that are not written keep opening with
   the old key.
3. After the session lifetime (30 days) has passed, every live row has been
   written since step 1 or has expired. Remove the old key.

A key that leaked needs no grace period: deploy without it, and every session
sealed under it signs out.
