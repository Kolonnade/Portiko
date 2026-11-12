# Serving the provider under a path

`ISSUER` is the provider's public base URL, and its path decides where the
provider lives. With no path, Portiko owns the whole host:

    ISSUER=https://accounts.example.com      ->  /signin, /oauth/authorize, ...

With a path, every route moves under it, so a site can be its own identity
provider next to its own pages:

    ISSUER=https://go.example.com/id         ->  /id/signin, /id/oauth/authorize, ...

There is no separate setting. `Config.BasePath()` reports the prefix (`/id`, or
`""` at the root), computed once from the issuer.

## What carries the prefix

Discovery (`/id/.well-known/openid-configuration`, built by `zitadel/oidc` from
the issuer), the `jwks_uri` and every endpoint it lists, the Portiko
configuration documents (`/id/.well-known/portiko-configuration` and the legacy
path), the `/id/accounts/v1/*` API, every redirect, and every link, form action
and `fetch` in the built-in pages. Templates get the prefix as `{{.Base}}`
(`{{$.Base}}` inside a `range`); write `{{.Base}}/signin`, not `/signin`. The passkeys page
(`{{.Base}}/u/{n}/passkeys`) follows the same rule. A `TEMPLATE_DIR` override
that hard-codes root paths keeps working only at the root.

## Mounting it

Give the host's mux the provider at the issuer's path, with a trailing slash,
and do not wrap it in `http.StripPrefix`. `Handler()` strips the prefix itself
and answers 404 for anything outside it:

```go
mux.Handle("/id/", p.Handler()) // ISSUER=https://go.example.com/id
```

The host keeps its own `/`, `/health` and `/u/{key}`. A request for `/id` is
redirected to `/id/`. At the root, `Handler()` is mounted at `/`, as before.

The `portiko` command serves the handler on its own port, so behind a reverse
proxy forward `/id/` to it unchanged (no path rewriting).

## Cookies

The browser cookie (`accounts_sso`) is limited to `Path=/id`, so the host never
receives it and a host cookie of any name cannot be confused with it. The name
is unchanged: renaming it would sign out every root-mounted deployment's
people, and the path already keeps it apart. At the root the path stays `/`.

A relying party's own cookies (`accounts_rp_session`, `portiko_rp_flow`) belong
to the site and stay at `Path=/`.

## Caveats

- With a path issuer, the standalone `portiko` command's health check moves to
  `/id/health`; `/health` is a 404.
- `Path=/id` keeps the cookie off requests to the host's own paths. It does not
  isolate it from same-origin script: a page of the host can `fetch` the
  provider's API, and the browser attaches the cookie. (HttpOnly still keeps
  script from reading the value.)
- The provider's CSRF check on form posts (`sameOrigin`) compares origins, so
  once embedded, every page of the host counts as same-origin. Do not host
  untrusted content on the same origin.
- Moving an existing deployment from the root to a prefix leaves the old
  `Path=/` `accounts_sso` cookie in browsers. Sign-out clears only the
  `Path=/id` one and does not clear the old one; it is inert (the new routes
  never read it at `/`) and expires on its own. A fresh deployment is unaffected.
- `ISSUER`'s path is validated at startup: segments of letters, digits and
  `. _ ~ -` only, no empty segments (one trailing slash is accepted and trimmed), no query or fragment.
- Paths are matched on the segment boundary: `/idx` and `/idhealth` are the
  host's, not the provider's. A non-clean path under the prefix (`/id//signin`)
  is redirected (308) to its clean form with the prefix, and `/id` to `/id/`.
- The conformance harness needs a root issuer.

## A site on the same origin

`rp` works with an issuer on the site's own origin. Use the issuer with its
path as `rp.Config.Issuer`, and a `RedirectURL` under the site's own paths:

```go
rp.New(ctx, rp.Config{
    Issuer:      "https://go.example.com/id",
    RedirectURL: "https://go.example.com/auth/callback",
    // ...
})
```

Register that exact URL with `RegisterClient`. The WebAuthn relying party ID
and origins are unaffected by the path: `WEBAUTHN_RP_ID=go.example.com`,
`WEBAUTHN_RP_ORIGINS=https://go.example.com`.
