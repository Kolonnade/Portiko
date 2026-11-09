# Conformance runs

The [opinions](opinions.md) make the OpenID Foundation's conformance suite a
release gate: no release goes out until it has run. This page is the plan for
running it, written before the first run so that run has something to be checked
against.

## Status

**Run, not passing.** The first run (2026-11-09, below) stopped on the PKCE
requirement before most modules ran. No release has been tagged. The first will be `v0.1.0` (the
repository has no tags; `v0.x` because the embedding API is still moving). It is
cut from the commit the first passing run tested.

## What gates a release

- **OpenID Connect Basic OP** (`oidcc-basic-certification-test-plan`)
- **OpenID Connect Config OP** (`oidcc-config-certification-test-plan`)

RP-Initiated Logout and Back-Channel Logout join the gate in a later release;
release notes until then say they were not run.

## Where it runs

On **cameron**, inside a disposable **Linux** Tart VM. Not on a developer laptop,
and not in one of cameron's macOS goldens: Docker cannot run inside a macOS
guest on Apple Silicon, and a Linux guest does not take one of Apple's two macOS
guest slots. Follow cameron's ground rules in the Homelab repository
(`cameron/tart-ui-test-vm.md`): take a `tart-lease` slot, check disk and memory
first, share nothing read-write into the guest, and ask Brennan before each
step that changes anything on cameron.

Inside the guest, all on one host so no name resolution crosses a boundary:

- the suite's prebuilt images (`docker-compose-prebuilt.yml` from
  `gitlab.com/openid/conformance-suite`), serving on `https://localhost.emobix.co.uk:8443`
- PostgreSQL for Portiko
- the conformance harness below, serving Portiko over HTTPS

The suite runs in containers, so Portiko's issuer has to be a name the
containers resolve to the guest (for example `host.docker.internal`, mapped with
`extra_hosts: host-gateway`). The suite does not verify TLS certificates, so a
self-signed one generated at startup is enough.

## The harness

The suite drives the authorization endpoint with its own headless browser,
which cannot create or use a passkey. A person clicking through ~35 tests every
release is not a gate anyone keeps, so the run is automated by a harness:

- **Test-only.** It lives behind a `conformance` build tag and is never part of
  the `portiko` binary. It adds no route, flag or bypass to the provider.
- **The real ceremony.** It embeds the provider (`provider.Migrate`,
  `provider.New`, `RegisterClient`), enrolls one test account through
  `register/start` → `verify` → `finish` with `descope/virtualwebauthn` (already
  a test dependency), and keeps that credential in memory.
- **Signing in.** It wraps the provider's handler. When the suite's browser is
  sent to `GET /signin?authRequestID=…`, the harness runs `login/start` and
  `login/finish?authRequestID=…` in-process with the browser's own cookies and a
  virtual assertion, then relays the `Set-Cookie` headers and redirects to the
  `redirect` login/finish returns, just as `signin.html` does after a real
  passkey. (Not to `/login?authRequestID=…`: with `prompt=login` that sends the
  browser straight back to `/signin`, a loop.)
  Every other request goes straight to the provider.
- **Clients.** Two confidential, first-party clients (`client_secret_post`, so
  no consent screen) with the redirect URI
  `https://localhost.emobix.co.uk:8443/test/a/portiko/callback`, plus whatever
  each plan's configuration asks for.
- **Configuration.** `REGISTRATION=open`, a fresh database per run, the
  issuer and WebAuthn origin both set to the harness's HTTPS address.

Plans are started with the suite's `scripts/run-test-plan.py` against a JSON
configuration kept beside the harness, so a run is one command.

## What a pass means

Every module `PASSED`, or `WARNING` with the warning written down here and
accepted. Modules that end in `REVIEW` (the ones that expect the provider to
show an error page instead of redirecting, such as an unregistered
`redirect_uri`) need a person to look at the captured page; record who looked
and when. Any `FAILED` blocks the release.

## Results

Record each run here: date, Portiko commit, suite version, plan, and the
outcome per module, with the exported result files kept alongside.

The harness is `conformance/` (`go test -tags conformance ./conformance/`), and
a run is `conformance/run-vm.sh` on cameron: a disposable
`ghcr.io/cirruslabs/ubuntu:24.04` guest, inputs streamed in rather than shared,
results streamed out, the clone deleted on exit.

### 2026-11-09 — not passing: PKCE

| | |
|---|---|
| Portiko | `3fdf98e` |
| Suite | `release-v5.3.4` (`23353b36`), prebuilt images of the same tag, arm64 |
| Plans | `oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]`, then `oidcc-config-certification-test-plan` |
| Outcome | Aborted by `run-test-plan.py` after three consecutive INTERRUPTED modules; the Config OP plan never started; nothing exported |

| Module | Result |
|---|---|
| `oidcc-server` | INTERRUPTED — authorization refused: `PKCE with code_challenge_method=S256 is required` |
| `oidcc-response-type-missing` | FINISHED (refused with `invalid_request` as expected) |
| `oidcc-userinfo-get` | INTERRUPTED — same PKCE refusal |
| `oidcc-userinfo-post-header` | INTERRUPTED — same PKCE refusal |
| `oidcc-userinfo-post-body` | INTERRUPTED — same; run aborted here |

Cause: Portiko requires S256 PKCE from every client, confidential ones
included (`provider/oidc.go`, `CreateAuthorizationRequest`). The suite's OIDC
OP modules send no PKCE; only `oidcc-ensure-request-with-valid-pkce-succeeds`
does. So nearly every Basic OP module fails at the authorization endpoint
until either the requirement or the gate changes. The harness was never asked
to sign in (0 ceremonies). An earlier attempt the same day, at `3c257e6`, ran
no module: macOS tar had added AppleDouble `._*` files to the suite's
`certs-keys`, fixed in `3fdf98e`.

Expected next, from reading the code rather than a run: userinfo returns only
the openid and profile claims (`SetUserinfoFromToken` ignores the granted
scopes), so `oidcc-scope-email` is likely to fail once PKCE is settled.
