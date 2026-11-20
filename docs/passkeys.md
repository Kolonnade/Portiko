# Managing passkeys

A signed-in person can see, rename and revoke the passkeys on their account.

## The page

`GET /u/{n}/passkeys` (under the issuer's path prefix, if it has one) lists the
account's passkeys: the name, the passkey provider it came from, when it was
created and when it was last used. Each has a rename field and a remove button.
The home and profile pages link to it. With `PASSWORDS=allow` the same page has
a Password section ([passwords.md](passwords.md)), and every deployment's page
has an **Add a passkey** link, which runs the email-code sign-in on the device
so it can create one.

Sites that want to send someone there link to `{issuer}/passkeys`, which
redirects to the default account's page (or to sign-in first), the way
`{issuer}/profile` does. With `ISSUER=https://go.example.com/id` that is
`https://go.example.com/id/passkeys`.

The provider shown comes from the passkey's AAGUID (`internal/passkey`). Many
platform authenticators report none on purpose, and an AAGUID outside the short
table is not guessed at; both read "Unknown".

## The endpoints

All are under `/accounts/v1/` and answer in the API's usual JSON, with
`{"error", "error_description"}` bodies on failure. The account is named
explicitly. `account` is required in the body of the two POSTs (400
`invalid_request` without it), so a state-changing call never acts on a guessed
account. The read-only `GET` and the page may omit it and get the browser's
default account.

| Request | Does |
|---|---|
| `GET /accounts/v1/passkeys?account=n` | `{"account", "passkeys": [{"id", "name", "provider", "created_at", "last_used_at"}]}`; `last_used_at` is `null` until first use |
| `POST /accounts/v1/passkeys/{id}/rename` `{"account", "name"}` | Renames; answers with the passkey list |
| `POST /accounts/v1/passkeys/{id}/revoke` `{"account"}` | Deletes; answers with the passkey list and a `signal` |

The two POSTs need `Content-Type: application/json` and a request from the
provider's own origin (`Origin`, or `Referer`), as the profile and sign-in
endpoints do. No session is 401 `login_required`.

Revoke also needs a sign-in (a passkey, or the account's password) within the last ten minutes
(`provider.ReauthWindow`), so a stolen session cookie cannot remove the holder's
way back in: `403 reauthentication_required`, which the page answers by signing
in again and retrying, as the email page does. A session signed in with a
passkey enrolled through recovery cannot revoke for a week:
`403 recovery_hold` ([emails.md](emails.md#the-recovery-hold)).

Statuses: `400` for a bad name, `404 not_found` for a passkey that does not
exist **or belongs to another account** (the same answer, so an id never
reveals itself), and `409 cannot_revoke_last_passkey` when it is the account's
only one and the account has no password. With nothing to fall back on,
removing the last passkey locks the person out, so it is refused. An account
with a password (`PASSWORDS=allow`, [passwords.md](passwords.md)) may revoke its
last passkey; its password then becomes the last credential and cannot be
removed. The check is race-safe: revoke locks the account's credential rows
(`SELECT ... FOR UPDATE`), then its password row, and counts and deletes in one
transaction, so two simultaneous revokes of the last two leave one, and so do a
revoke and a password removal. A
passkey that is not the caller's is a 404 before the last-passkey rule is
considered.

## Audit

Both write `auth_audit` rows with the address and user agent:
`credential.renamed` (detail: `credential_id`, `from`, `to`) and
`credential.revoked` (detail: `credential_id`, `name`, `provider`).

## Signals to the passkey provider

Deleting the server's record does not remove the passkey from the person's
password manager. A revoke therefore returns a `signal`, and the page passes it
to `PublicKeyCredential.signalAllAcceptedCredentials`:

```json
{"rp_id": "example.com", "users": [{"user_id": "<handle>", "credential_ids": ["<id>", ...]}]}
```

One entry per WebAuthn user handle, listing the credentials still valid for it
(empty if none), so the provider can hide or remove the rest. It is
feature-detected and best effort. A signal sent while a new passkey is still
being enrolled on the same handle may briefly hide the new one: where the browser lacks the API nothing
happens, and the passkey simply remains in that device's list until the person
deletes it there. A script that calls the API directly can send the same
signal.

### A passkey the provider no longer knows

A device can go on offering a passkey after the server has forgotten it: it was
revoked from another browser, its account was deleted, or the database was
reset. `POST /accounts/v1/login/finish` answers an assertion made with a
credential it has no record of with its own error, rather than the generic
`401 authentication_failed`:

```json
{"error": "unknown_credential", "rp_id": "example.com", "credential_id": "<base64url>"}
```

The sign-in page passes `rp_id` and `credential_id` to
`PublicKeyCredential.signalUnknownCredential`, where the browser has it, so the
passkey provider stops offering the passkey, and then offers the email code.

The answer reveals nothing about accounts. The credential id came from the
caller's own device, a removed passkey and one that never existed here get the
same answer, and it is reached only with a valid challenge from `login/start`.
A passkey that is still on record but whose account is disabled gets the
generic answer, as every other failure does.

Renaming a passkey to the name it already has changes nothing and writes no
audit row.

Rename sends **no** signal. WebAuthn has no per-credential name signal;
`signalCurrentUserDetails` names the account's *user*, which the profile page
already sends when the display name changes, and that is a different thing from
the label on one passkey. The label here is Portiko's own, shown in the
passkeys list; it does not change what the person's password manager shows for
that credential.
