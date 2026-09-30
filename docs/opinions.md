# Opinions

Portiko is opinionated on purpose. The positions below are the ones that shape the API, and a change that contradicts one of them will be turned down however good the code is — so they are written here rather than discovered at review time.

## Identity, never authorization

Portiko answers **who is this person**. It never answers **what may they do**. No roles, no permissions, no admin flags, in the provider or in its tokens.

This is not a missing feature. A role means nothing without context — admin of *which* group, on *which* server? — and a role inside a token is stale for that token's lifetime, so demoting someone leaves them powerful until it expires. Your application knows what its data means and can read its own rules fresh on every request. It should.

## The protocol comes from `zitadel/oidc`

Authorize, token, refresh, discovery, introspection, revocation, end-session: all of it comes from [`zitadel/oidc`](https://github.com/zitadel/oidc), which is maintained and exercised far beyond this project. Portiko supplies the storage, the ceremonies and the product surface around it.

The OpenID Foundation's conformance suite runs before a release goes out. "It works against our own client" is not evidence.

## Passkeys are the credential

There are no passwords to store, reset or leak. A one-time code by email exists for enrollment and recovery and is never a way to sign in on its own.

The rules that cost other implementations dearly are built in: Backup Eligible is immutable after registration, Backup State is not; a synced passkey reports a sign count of zero forever and that is normal; a counter never moves backwards; challenges live in the database and are consumed in the same statement that reads them.

## One token, one subject, one audience

Every access token names exactly one subject and exactly one audience. A token valid at two services is the audience-confusion attack the model exists to exclude, so the verifier refuses a token carrying more than one audience rather than checking membership.

The subject is opaque, stable and random — never an email address, never a row id. Email addresses change; subjects do not.

## The browser holds an identifier, never a credential

Sessions are database-backed and revocable. The browser gets an opaque identifier; tokens stay on the server. Revoking is a row, not a wait for an expiry.

Refresh tokens rotate, and reuse of a rotated token revokes the whole grant rather than merely failing.

## The server never guesses which account

When several accounts are signed in, the client says which one it means and an ambiguous request goes to the chooser. See [multiple-accounts.md](multiple-accounts.md).

## PostgreSQL, and nothing pinned to one process

State lives in PostgreSQL, including the in-flight ceremonies, so a deployment can run more than one replica and survive a restart mid-sign-in. Migrations ship with the library. There is no in-memory store that quietly makes a deployment single-instance.

## Failures are generic outward, decisive inward

Every failed sign-in returns the same error whatever went wrong, because the difference between "no such account" and "wrong code" is an enumeration oracle. The server log names the step that actually failed — resolving the credential, consuming the challenge, validating the assertion — because without it an investigation is guesswork.

## Extension points where products differ

The profile is an interface, not a schema. Display name, avatar, whatever your product means by a person's presentation: implement it, and the claims follow. The sign-in pages, the avatar set and the account chooser are templates you can replace. What is *not* replaceable is anything above: those are the parts that are dangerous to get wrong.

## Standards over invention

Where a specification exists, Portiko follows it: OpenID Connect and its Back-Channel Logout, RFC 8252 for native apps, OpenID Connect Native SSO for an app family sharing a device, RFC 8693 for token exchange, RFC 8417 and RFC 8935 for pushed security events, RFC 9068 for access-token format, RFC 9700 for the security practices.

Inventing a protocol here means inventing its attacks too.
