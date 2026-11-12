# Managing passkeys

A signed-in person can see, rename and revoke the passkeys on their account.

## The page

`GET /u/{n}/passkeys` (under the issuer's path prefix, if it has one) lists the
account's passkeys: the name, the passkey provider it came from, when it was
created and when it was last used. Each has a rename field and a remove button.
The home and profile pages link to it.

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
explicitly (`account` in the query or body), never guessed.

| Request | Does |
|---|---|
| `GET /accounts/v1/passkeys?account=n` | `{"account", "passkeys": [{"id", "name", "provider", "created_at", "last_used_at"}]}`; `last_used_at` is `null` until first use |
| `POST /accounts/v1/passkeys/{id}/rename` `{"account", "name"}` | Renames; answers with the passkey list |
| `POST /accounts/v1/passkeys/{id}/revoke` `{"account"}` | Deletes; answers with the passkey list and a `signal` |

The two POSTs need `Content-Type: application/json` and a request from the
provider's own origin (`Origin`, or `Referer`), as the profile and sign-in
endpoints do. No session is 401 `login_required`.

Statuses: `400` for a bad name, `404 not_found` for a passkey that does not
exist **or belongs to another account** (the same answer, so an id never
reveals itself), and `409 cannot_revoke_last_passkey` when it is the account's
only one. With no password to fall back on, removing the last passkey locks the
person out, so it is refused. The check is race-safe: revoke locks the
account's credential rows (`SELECT ... FOR UPDATE`) and counts and deletes in
one transaction, so two simultaneous revokes of the last two leave one. A
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
feature-detected and best effort: where the browser lacks the API nothing
happens, and the passkey simply remains in that device's list until the person
deletes it there. A script that calls the API directly can send the same
signal.

Rename sends **no** signal. WebAuthn has no per-credential name signal;
`signalCurrentUserDetails` names the account's *user*, which the profile page
already sends when the display name changes, and that is a different thing from
the label on one passkey. The label here is Portiko's own, shown in the
passkeys list; it does not change what the person's password manager shows for
that credential.
