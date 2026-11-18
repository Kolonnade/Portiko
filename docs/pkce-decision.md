# PKCE and the conformance gate

**Decision needed from Brennan.** v0.1.0 is blocked. Portiko refuses every
authorization request that has no S256 PKCE challenge. The OpenID
Foundation's Basic OP modules send no PKCE, so almost none of them can get
past the authorization endpoint. This page sets out where the rule comes from,
what the standards ask for, and the options.

## What happened

On 2026-11-09 the Basic OP plan ran in a disposable Linux VM on cameron. It
used Portiko `3fdf98e` and suite `release-v5.3.4`. The full record is in
[conformance.md](conformance.md#2026-11-09--not-passing-pkce).

- `oidcc-server`, `oidcc-userinfo-get`, `oidcc-userinfo-post-header` and
  `oidcc-userinfo-post-body` were all sent back to the suite's callback with
  `error=invalid_request`,
  `error_description=PKCE with code_challenge_method=S256 is required`.
  The suite marks that INTERRUPTED: "The authorization was expected to
  succeed, but the server returned an error".
- After three INTERRUPTED modules in a row, `run-test-plan.py` judges the
  server unhealthy and aborts. The Config OP plan never started.
- The harness never had to sign anyone in (0 ceremonies). The failure happens
  before a sign-in would start.

This is a property of the provider, not of the harness or the VM. The same
refusal is visible in `TestPKCEAndRedirectURIsAreEnforced`.

## Where the rule comes from

`provider/oidc.go`, in `CreateAuthRequest`:

```go
// PKCE for every client, confidential ones included: a client secret does
// not protect a code stolen from the redirect itself.
if req.CodeChallenge == "" || req.CodeChallengeMethod != oidc.CodeChallengeMethodS256 {
    return nil, oidc.ErrInvalidRequest().WithDescription("PKCE with code_challenge_method=S256 is required")
}
```

The rule appears only in that comment. [opinions.md](opinions.md) does not
mention PKCE. It does say "the OpenID Foundation's conformance suite runs
before a release goes out", so two of the project's stated commitments now
conflict.

Portiko's own relying-party package (`rp/client.go`) always sends PKCE
(`zrp.WithPKCE`). Every site built on `rp` is unaffected by any of the options
below. They change only what a client that does *not* send PKCE is allowed to
do.

## What the standards say

- **OpenID Connect Core 1.0** does not mention PKCE. A code-flow request with
  neither PKCE nor `nonce` is valid. The suite tests exactly that:
  `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`.
- **RFC 9700 (OAuth 2.0 Security BCP), §2.1.1:**
  - Public clients MUST use PKCE.
  - For confidential clients PKCE is RECOMMENDED, not required.
  - Confidential OpenID Connect clients MAY rely on `nonce` instead.
  - Authorization servers MUST support PKCE.
  - Authorization servers MUST refuse a `code_verifier` at the token endpoint
    when the authorization request had no challenge (downgrade protection).
- **OAuth 2.1 (draft)** takes the same position: PKCE is required for public
  clients, and confidential clients may use other protection against code
  injection.
- **Certification.** The suite's base OIDC test class
  (`AbstractOIDCCServerTest`) never adds PKCE. Only
  `oidcc-ensure-request-with-valid-pkce-succeeds` does. An OP that requires
  PKCE from everyone cannot pass Basic OP. Patching the suite to send PKCE
  would produce results the Foundation would not accept as Basic OP.

Portiko is stricter than every one of these.

## What Portiko already has if the rule is relaxed

- **Downgrade protection is already in zitadel/oidc.**
  `op.AuthorizeCodeChallenge` rejects a `code_verifier` when no challenge was
  stored ("code_verifier unexpectedly provided"). It also rejects a missing or
  wrong verifier when a challenge was stored. RFC 9700's MUST is met without
  new code.
- **S256 only.** Requiring S256 whenever a challenge is sent would stay.
  `plain` keeps being refused.
- **Public and native clients** would still have to send PKCE. They have no
  secret, so PKCE is their only protection.
- **Confidential clients** authenticate at the token endpoint with their
  secret. A stolen code is useless without that secret. What PKCE adds for them
  is protection against *code injection*: an attacker plants a code from their
  own session into the victim's client. `nonce` also covers that case, and so
  does a client that binds `state` to the browser.

## Options

### A. Per-client opt-out, default unchanged

Add a `RequirePKCE` setting to `provider.Client`. It defaults to true, needs a
column in `oauth_clients`, and gets a CLI flag. The conformance clients set it
to false; every other client keeps today's behavior.

- **For:** keeps the strict default for every real deployment.
- **Against:** the suite certifies a configuration nobody ships by default.
  A setting whose only known user is the test suite is close to the "bypass"
  the harness was designed not to need.
- **Effort:** small, plus a migration.

### B. Require PKCE from public clients only *(recommended)*

Change the check to require S256 PKCE when the client has no secret. A
confidential client may omit PKCE. If it sends a challenge, it must be S256
and is enforced at the token endpoint.

- **For:**
  - Matches RFC 9700 and OAuth 2.1.
  - Lets Basic OP run against exactly what ships.
  - Downgrade protection is already present.
  - Portiko's own `rp` sites keep using PKCE.
- **Against:** a confidential third-party client could skip both PKCE and
  `nonce`. It would then be exposed to code injection. The usual mitigation is
  in the client, not the server.
- **What not to add:** "PKCE or nonce". It would fail
  `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`.
- **Effort:**
  - About a three-line change in `CreateAuthRequest`.
  - Update `TestPKCEAndRedirectURIsAreEnforced` so it uses a public client for
    the refusal case, and add a test that a confidential client succeeds
    without PKCE.
  - Add an entry in opinions.md stating the rule.

### C. Keep the rule and change what counts as a pass

Record the PKCE-less modules as accepted failures in conformance.md and
release.

- **Against:**
  - It contradicts "any FAILED blocks the release".
  - Most of the Basic OP plan would never run past the authorization
    endpoint: ID token, userinfo, prompt, max_age, code reuse, refresh. The
    gate would no longer show much.
  - Portiko could not describe itself as passing Basic OP.
  - `run-test-plan.py` aborts after three failures in a row, so even
    collecting the list needs changes to how the run is driven.

### D. Hold

Ship nothing. No tag or release until you decide.

## Recommendation

**B.** The rule as written goes further than the Security BCP, and it is in
direct conflict with the gate Portiko committed to publicly. Requiring PKCE
from public clients keeps the protection where it is essential. It also
keeps the tested configuration identical to the shipped one. Choose A instead
if keeping PKCE mandatory by default for every confidential client matters
more than certifying the default configuration.

## What follows each choice

| Choice | Next |
|---|---|
| A or B | Code change and tests, then rerun both plans in a fresh VM. The rerun will show the next issue (below) and the four modules that end in REVIEW. Release only if every module passes. |
| C | Rewrite "What a pass means" in conformance.md, and change how the run continues after failures. Then rerun. |
| D | Nothing more. The VM is already deleted. |

## A second issue the rerun will probably show

`SetUserinfoFromToken` (`provider/oidc.go:248`) always fills userinfo as if
only `openid` and `profile` were granted. As a result:

- The `email` scope's claims are never returned from userinfo, even when
  granted.
- The Go harness test observed this: userinfo returned only `sub` and
  `updated_at`.
- `email` is also absent from the ID token.

`oidcc-scope-email` (and probably `oidcc-scope-all`) should fail on it. This
was found by reading the code; no conformance run has reached it yet. The fix
is to fill userinfo from the token's granted scopes. It is a separate decision
from PKCE.

## Also needs a person regardless

Four modules expect an error page instead of a redirect for a bad
`redirect_uri`, and end in REVIEW:

- `oidcc-ensure-registered-redirect-uri`
- `oidcc-ensure-redirect-uri-in-authorization-request`
- `oidcc-redirect-uri-query-added`
- `oidcc-redirect-uri-query-mismatch`

Someone has to look at the captured page and record who looked and when.

## State of the repository

No tag, no release. The conformance work is on `origin/main`:

| Commit | |
|---|---|
| `3c257e6` | Harness and Go test |
| `3fdf98e` | Run-script fix |
| `03a46b8` | The run recorded in conformance.md |
