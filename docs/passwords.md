# Passwords

Portiko is passkey-first, and passkeys stay the recommended credential. Some
people cannot use one at all: an old computer whose browser has no WebAuthn,
platform or cross-device, is enough. For them a deployment can turn on a
password, off unless it says so.

```
PASSWORDS=allow
```

`off`, or leaving it unset, is the default. Any other value stops start-up.
This is the one exception to [Passkeys are the credential](opinions.md#passkeys-are-the-credential);
the reasons it is narrow are below.

## What it changes

With `PASSWORDS=allow`:

- **After the emailed code**, in enrollment and in recovery, the sign-in page
  asks the person to choose: **Create a passkey** (first, and recommended) or
  **Set a password**. With passwords off the page goes straight to the passkey,
  as before.
- **Sign-in** takes an email address and password on the same page as the
  passkey button. Any verified address on the account works.
- **The account page** (`/u/{n}/passkeys`) has a Password section to add,
  change or remove one, and an account with a password can confirm a sensitive
  change with it instead of a passkey.
- **Tokens** say how the session was made: `amr` is `["pwd"]` after a password
  sign-in, and `["swk","user"]` or `["hwk","user"]` after a passkey, as
  before. A site that wants a passkey for something sensitive can check.

The emailed code is still only for enrollment and recovery. It can lead to a
password being set; it never signs anybody in on its own.

Turning passwords off again stops every password from signing in and from
being set. The rows stay, an account can still remove its password, and an
account that had only a password recovers with its email and creates a
passkey.

## The policy

NIST SP 800-63B's rules for a password that is the only factor:

- **At least 15 characters**, counted as characters after Unicode NFKC
  normalization, and at most 1024 bytes. A few ordinary words with spaces
  between them is the intended shape.
- **No composition rules.** No required digits, capitals or symbols, and no
  expiry.
- **Refused when easily guessed**: on a small list of common passwords embedded
  in the binary (`internal/password/common.txt`), one short unit repeated
  (`passwordpassword`), a run along the alphabet, the digits or a keyboard row
  (`1234567890123456`, `qwertyuiopasdfgh`), or the account's own address or the
  service's name with filler. Case and punctuation are ignored when comparing.
  Nothing is ever sent anywhere to be looked up.

A refused password is `400 weak_password` with the reason in
`error_description`, worded to be shown as it is.

## Storage

Argon2id (`golang.org/x/crypto/argon2`), 19 MiB, two passes, one lane, a
16-byte random salt and a 32-byte key, stored in PHC form
(`$argon2id$v=19$m=19456,t=2,p=1$…`) in the `passwords` table, one row per
account. The parameters travel with the hash: raising them rehashes each
password at its next sign-in.

## Guessing is bounded

A password, unlike a passkey assertion, can be guessed, so three limits apply:

| Limit | Budget |
|---|---|
| `POST /accounts/v1/login/password` per IP | 60 / hour |
| the same, per address named | 10 / hour |
| per account, across every address and IP | 5 failures free, then a wait of 30 s doubling per failure up to 1 hour |

The per-account backoff lives in the password row. Each attempt is counted
before it is checked, under the row's lock, so a burst of parallel guesses
queues rather than all slipping in before the first failure is recorded. While
an account waits, even the right password is refused. A success clears it.

Every failure is the same `401 authentication_failed`: a wrong password, an
unknown address, an account with no password, a disabled one and one waiting
out its backoff. Each runs one Argon2id verification, so the time taken does
not tell them apart either. The server log names the real step.

`RATE_LIMIT_EXEMPT` skips the two endpoint limits, as it does everywhere
([rate-limits.md](rate-limits.md)); the per-account backoff still applies.

## Recovery and the hold

Recovery with a password is the forgotten-password path: the code is accepted,
the person chooses **Set a password**, and the account's password is set, or
replaced if it had one. Its passkeys are never touched.

A password set through recovery is held for a week exactly as a recovered
passkey is ([emails.md](emails.md#the-recovery-hold)): a session signed in with
it cannot change the primary address, remove an address, revoke a passkey, or
change or remove the password. A session that is itself held and adds a
password gives the new password the same hold. The primary address is sent a
password notice (`SendPasswordChanged`, with `Recovery` set) and the audit
trail gets `password.set` or `password.changed` and `account.recovered`.

## The last credential

An account can never remove its last way in. With a password on the account
the last passkey may be revoked; then the password is the last credential and
`POST /accounts/v1/password/remove` answers `409
cannot_remove_last_credential`. A password-only account adds a passkey by
signing in with its email and code on a device that has passkeys (the page's
**Add a passkey** link), and can then remove the password from a session that
is not held, such as one signed in with that password.

Revoking a passkey and removing the password lock the account's passkey rows
and then its password row, in that order, so doing both at once leaves one.

## The endpoints

Under `/accounts/v1/`, JSON in and out, with `{"error", "error_description"}`
bodies on failure. **Every POST needs `Content-Type: application/json` and a
request from the provider's own origin** (`Origin`, or `Referer`): a password
is not bound to the origin the way a passkey ceremony is, so this is what stops
another site from signing a browser in. A form post is `415`, another origin
`403`. With passwords off, every endpoint but `GET password` and
`password/remove` answers `404 passwords_not_enabled`.

| Request | Does |
|---|---|
| `POST /register/verify` `{"email","code"}` | as before, plus `"password_token"` when passwords are allowed |
| `POST /register/password[?authRequestID=]` `{"token","password"}` | finishes the verified code with a password instead of a passkey; answers as `register/finish` does (`{"status":"signed_in","subject","account","redirect"}`) |
| `POST /login/password[?authRequestID=]` `{"email","password"}` | signs in; answers as `login/finish` does |
| `GET /password?account=n` | `{"account","allowed","password": null \| {"created_at","updated_at","last_used_at"},"reauth_until","held_until"}` |
| `POST /password` `{"account","password"}` | adds or changes the password; answers as `GET` |
| `POST /password/remove` `{"account"}` | removes it; answers as `GET`; `404 not_found` when there is none |

`register/password` keeps its token when the password is refused for the
policy, so the person can choose another; once it succeeds the token, and the
passkey options issued with it, are spent. Adding a password needs a sign-in
within `ReauthWindow` (10 minutes); changing or removing one also must not come
from a held session (`403 reauthentication_required`, `403 recovery_hold`).
Signing in again with the password counts.

When `?authRequestID=` names a site's pending sign-in, `redirect` is the
provider URL that completes it; a client follows it to the site's callback, as
a browser would.

## A scripted client

An end-to-end suite can enroll and sign in with no browser: plain HTTP, a
cookie jar, `Origin` set to the issuer's origin on the POSTs, and
[`TEST_MAIL_DOMAINS`](test-mail.md) for the code.

1. `GET` the site's login URL and follow redirects. The client lands on
   `{issuer}/signin?authRequestID=…`; keep the id.
2. `POST /accounts/v1/register/start?authRequestID=…` `{"email"}` → `202`.
3. Read the code from the provider's log (`to=<address> code=NNNNNN`).
4. `POST /accounts/v1/register/verify?authRequestID=…` `{"email","code"}` →
   take `password_token`.
5. `POST /accounts/v1/register/password?authRequestID=…`
   `{"token","password"}` → `GET` the `redirect` and follow redirects back to
   the site, which completes its code exchange.

To sign in later, step 1 again, then `POST
/accounts/v1/login/password?authRequestID=…` `{"email","password"}` and follow
its `redirect`.

## Audit and mail

`password.set`, `password.changed` and `password.removed` rows, with the
address and user agent and `{"recovery": bool}` where it applies. Every change
but the one that created the account sends `SendPasswordChanged` to the primary
address: a required `Mailer` method, with a `mail-password-changed.txt`
template for a deployment's own wording (`.Change` is `added`, `changed` or
`removed`; `.Recovery`, `.When`, `.ReviewURL`). Sign-in events gain
`password_set` and `password_signin_finished` ([sign-in-events.md](sign-in-events.md)).

## A replacement sign-in page

A deployment with its own `TEMPLATE_DIR` sees no password until its templates
offer one. The sign-in template receives `.Passwords` (whether to offer it) and
`.MinPassword`; the passkeys template receives `.Passwords`, `.Password` (nil
or the view above), `.MinPassword` and `.ReauthPassword`, which the account
pages also set as `REAUTH_PASSWORD` for the shared `passkey-reauth` script.
