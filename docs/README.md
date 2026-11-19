# Portiko documentation

Design notes written ahead of the code, so the implementation has something to be checked against.

| Document | What it covers |
|---|---|
| [opinions.md](opinions.md) | The positions that shape the API, and what a contribution will be measured against |
| [multiple-accounts.md](multiple-accounts.md) | Several accounts signed in at once: the session model, choosing an account at the provider, and how server-rendered sites, single-page applications and native apps each say which account they mean |
| [recovery.md](recovery.md) | What happens when someone loses their passkey, their email, or both: the ladder from a second passkey down to the operator, and the rules every path follows |
| [key-rotation.md](key-rotation.md) | How the signing key is stored, the one-off that encrypts an existing one, and the three-step rotation — including the emergency version and what forcing it costs |
| [passkeys.md](passkeys.md) | Listing, renaming and revoking an account's passkeys: the page, the `/accounts/v1/passkeys` endpoints, the last-passkey rule, audit rows, and which WebAuthn signals are sent |
| [emails.md](emails.md) | Backup addresses: the `MAX_EMAILS` limit, adding one with a code, making it primary, removing one, re-authentication, notices, claims, and the page's template data |
| [rp-sessions.md](rp-sessions.md) | A site's own sessions in PostgreSQL with `rp/session/pgstore`: configuration, what is sealed, pruning, and rotating the key |
| [rate-limits.md](rate-limits.md) | What is limited and by how much, why the per-address counters live in Postgres, and why `TRUSTED_PROXIES` has to be set behind a reverse proxy |
| [test-mail.md](test-mail.md) | The `TEST_MAIL_DOMAINS` setting: sign-in codes for reserved test domains go to the log so an end-to-end test can sign up; any other domain stops start-up |
| [sign-in-time.md](sign-in-time.md) | How long a sign-in may take: the sliding life of an authorization request, its cap, and how a request that runs out sends the person back to the site to start again |
| [sign-in-events.md](sign-in-events.md) | The opt-in hook that reports each stage of each sign-in attempt, what an event carries and never carries, and the page's report of a failed passkey dialog |

More will land as the code does: the protocol specification, a self-hosting guide, the threat model, and a guide to signing in across sites on different domains.
