# Email addresses on an account

An account can hold more than one verified email address. One is the
**primary**; the rest are **backups**. Every address on the account can sign in
and recover it, so losing access to one inbox (a changed job, a closed school
address) does not lose the account.

## The limit

`MAX_EMAILS` is how many addresses one account may hold, the primary included.
The default is 3; Load accepts 1 to 10. A `Config` built by hand with
`MaxEmails` zero gets the default.

## The page

`GET /u/{n}/emails` (under the issuer's path prefix, if it has one) lists the
account's addresses, marks the primary, and has buttons to make a backup the
primary or remove it, and a form to add an address. The home and profile pages
link to it.

Sites, and the address-change notices, link to `{issuer}/emails`, which
redirects to the default account's page (or to sign-in first), the way
`{issuer}/passkeys` does.

### Template data

A deployment with its own `TEMPLATE_DIR` can add an `emails.html`. Without one
the page answers 404 with a short message; the endpoints below still work, so a
deployment can build its own page on them. The template gets:

| Field | Type | Meaning |
|---|---|---|
| `.Base` | string | The issuer's path prefix, `""` at the root. Build every link and API URL from it |
| `.ServiceName` | string | `SERVICE_NAME` |
| `.Account` | int | The account number in this browser, for `account` in API calls |
| `.SID` | string | The session ID, for the `auth-watch` script |
| `.Emails` | list | One per address: `.ID` (int), `.Email` (string), `.Primary` (bool), `.VerifiedAt` (time.Time, UTC) |
| `.Primary` | string | The primary address, for scoping the re-authentication ceremony |
| `.Max` | int | The limit, `MAX_EMAILS` |
| `.CanAdd` | bool | Whether the account is under the limit |
| `.ReauthUntil` | *time.Time | When the account's last passkey ceremony stops counting for changes, or nil if it already has |

The built-in page also uses the `auth-watch` template, as the other account
pages do.

## The endpoints

All are under `/accounts/v1/` and answer in the API's usual JSON, with
`{"error", "error_description"}` bodies on failure. As with the passkey
endpoints, every POST needs `Content-Type: application/json`, a request from
the provider's own origin, and `account` in the body (400 `invalid_request`
without it). No session is 401 `login_required`.

| Request | Re-auth | Does |
|---|---|---|
| `GET /accounts/v1/emails?account=n` | — | The addresses |
| `POST /accounts/v1/emails/add` `{"account", "email"}` | yes | Sends a six-digit code to the address. `202 {"status": "code_sent", "account"}` |
| `POST /accounts/v1/emails/verify` `{"account", "email", "code"}` | — | Adds the address as a backup; answers with the addresses |
| `POST /accounts/v1/emails/{id}/primary` `{"account"}` | yes | Makes it the primary; answers with the addresses |
| `POST /accounts/v1/emails/{id}/remove` `{"account"}` | yes | Removes a backup; answers with the addresses |

"The addresses" is:

```json
{"account": 0, "max": 3, "reauth_until": "2026-11-18T22:10:00Z",
 "emails": [{"id": 12, "email": "a@example.com", "primary": true, "verified_at": "…"},
            {"id": 31, "email": "b@example.com", "primary": false, "verified_at": "…"}]}
```

The primary is listed first, then the backups in the order they were added.
`reauth_until` is `null` when a change would need re-authentication.

Statuses:

- `400 invalid_email` — `add` with something that is not a bare address.
- `409 email_limit_reached` — `add` or `verify` when the account already holds
  `MAX_EMAILS` addresses. This is about the caller's own account, so it is said
  plainly.
- `401 authentication_failed` — `verify` with a wrong, expired or missing code,
  too many guesses, **or an address that is already on an account**. One answer
  for all of them.
- `403 reauthentication_required` — see below.
- `404 not_found` — an `{id}` that does not exist **or belongs to another
  account** (the same answer).
- `409 cannot_remove_primary_email` — removing the primary. Make another
  address primary first.
- `429 rate_limited` — `add` shares the budgets of asking for a sign-in code (5
  per address and 30 per IP an hour) and `verify` those of submitting one (60
  per IP an hour). The code guesses count against the same ten-per-address-per-
  hour budget as a sign-in code ([rate-limits.md](rate-limits.md)).

### An address already on an account

`add` answers `202` whether or not the address is already on an account, this
one or another, and sends nothing when it is. `verify` then fails with the same
`401` as a wrong code. Nothing distinguishes "taken" from "free", so the endpoint
cannot be used to find out who has an account. An address registered by someone
else between `add` and `verify` fails the same way.

### Re-authentication

Adding an address, removing one and changing the primary each need a passkey
ceremony in the last ten minutes (`provider.ReauthWindow`), not just a session
cookie: each one decides which inboxes can recover the account, so a stolen
cookie that could do them would be a way to keep the account for good. Adding
counts, because an added address can recover the account.

A refusal is `403 reauthentication_required`. The page answers it by signing in
again as the same account (`GET login/start?email=<primary>`, then
`POST login/finish`), which refreshes the session's `authenticated_at`, and
retries. `verify` needs no fresh ceremony; the code proves the address and the
`add` before it was already checked.

## Signing in and recovering

A sign-in code or a recovery started with any verified address reaches the same
account. Registration (`register/start`) treats a backup like the primary: the
address has an account, so it is recovery.

## Notices

Adding, removing and changing the primary each send `Mailer.SendEmailChanged`
to **every address on the account**, and on a removal to the removed address
too. The `EmailNotice` carries `When`, `Change` (`added`, `removed`,
`primary_changed`), `Address`, `Previous` (the old primary, for a primary
change) and `ReviewURL` (`{issuer}/emails`). The built-in SMTP message says
what changed and to sign in and review the account if it was not you; it has
no link that undoes anything, because a security notice with an action link in
it is a phishing template.

The code for a new address is sent with `SendCode`, as a sign-in code is. Under
`TEST_MAIL_DOMAINS` it is logged the same way, so an end-to-end test reads it
with the same pattern ([test-mail.md](test-mail.md)).

`SendEmailChanged` is a required method of `provider.Mailer`. A custom mailer
must add it.

### Your own wording

With the built-in SMTP sender, a deployment can replace the text of any message
by putting a `text/template` in its `TEMPLATE_DIR`:

| File | Message | Data |
|---|---|---|
| `mail-code.txt` | A one-time code (sign-in, recovery, or confirming a new address) | `.ServiceName`, `.Code` |
| `mail-passkey-added.txt` | A passkey added to an existing account | `.ServiceName`, `.When`, `.Authenticator`, `.ReviewURL` |
| `mail-email-changed.txt` | An address added or removed, or the primary changed | `.ServiceName`, `.When`, `.Change` (`added`, `removed`, `primary_changed`), `.Address`, `.Previous`, `.ReviewURL` |

Each template's output is a `Subject: …` line, a blank line, then the body:

```
Subject: The addresses on your {{.ServiceName}} account changed

{{if eq .Change "added"}}{{.Address}} can now sign in to your account.
{{else if eq .Change "removed"}}{{.Address}} can no longer sign in to your account.
{{else}}{{.Address}} is now your main address.{{end}}

If this wasn't you, sign in and check your account: {{.ReviewURL}}
```

A message without its file keeps the built-in text. Every file is executed with
sample data at start-up, so an unknown field, a missing subject, or a
`mail-*.txt` that is not one of the three stops the provider from starting
rather than failing someone's sign-in. Keep the notice free of any link that
undoes the change. A deployment with its own `provider.Mailer` writes its own
text and ignores these files.

## Claims

`email` is always the primary, with `email_verified: true`, in all three places
a site can read it when its grant includes the `email` scope: the ID token, the
access token and userinfo. It is read when the token is issued or userinfo is
called, so a site sees a new primary at the person's next sign-in, token
refresh or userinfo call. Nothing is pushed to sites when the primary changes.
Key accounts by `sub`, which never changes, not by email.

## Audit and events

Each change writes an `auth_audit` row with the address and user agent:
`email.added` (detail: `email`), `email.removed` (detail: `email`) and
`email.primary_changed` (detail: `from`, `to`). Addresses in the detail are
redacted to the first character of the mailbox and the domain
(`a***@example.com`).

With `Options.OnSignInEvent` set, the changes are reported as the stages
`email_added`, `email_removed` and `email_primary_changed`
([sign-in-events.md](sign-in-events.md)). Like every event, they never carry an
address.
