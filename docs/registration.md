# Who may create an account

Signing in and recovering are for people who already have an account. Creating
one is a separate decision, and a deployment makes it with one setting.

## The setting

| `REGISTRATION` | A new account needs | Use it for |
|---|---|---|
| `open` | only the emailed one-time code | a public service |
| `code` | the emailed code **and** `BOOTSTRAP_CODE` | a private service, or enrolling the operator |
| `closed` | — nobody can create one | a private service whose people are all enrolled |

Set it explicitly. Left empty, it means `code` when `BOOTSTRAP_CODE` is set and
`open` otherwise — what a deployment written before the setting existed
expects — so a forgotten `BOOTSTRAP_CODE` would quietly open sign-up.

Portiko refuses to start when the two settings disagree: `code` without a
`BOOTSTRAP_CODE`, `open` with one, any other value, or a `BOOTSTRAP_CODE`
shorter than 16 characters (`openssl rand -hex 16` makes a good one). An
embedder that builds `provider.Config` itself skips those checks, so the
provider also fails closed at runtime: an unknown mode, or `code` with no code,
refuses every new account.

## The rules every mode follows

- **In `code` mode the code is needed for every new account, not only the
  first.** A code that only guarded the first account would reopen sign-up to
  anyone the moment the operator enrolled.
- **Existing accounts are never gated.** Their passkeys sign in, and asking for
  a code for an address that already has an account runs recovery, in every
  mode. A closed deployment that gated recovery would lock its own people out
  ([Recovery §5](recovery.md)). A site that wants a stricter rule — a
  single-owner admin site, say — enforces it in front of the provider.
- **A refusal looks like success.** `POST /accounts/v1/register/start` answers
  `202 code_sent` either way. When it refuses, nothing is stored and nothing is
  mailed, so there is no code to verify. The response never says whether an
  address has an account or whether registration is closed.
- **Guessing is bounded.** The code travels in `register/start`, which is rate
  limited per address and per IP ([Rate limits](rate-limits.md)), and is
  compared in constant time. Refusals are logged.

## Deciding at runtime: `RegistrationPolicy`

A site that embeds the provider and decides who may join from its own data (an
admin toggle, an allow list) sets `provider.Options.RegistrationPolicy`:

```go
RegistrationPolicy: func(ctx context.Context, email string) (allowed bool, message string, err error)
```

- **When it runs.** At the start of registration (`register/start`), with the
  normalized email, before any code is mailed or row stored. It runs once per
  request, so a change in the site's data takes effect on the next request.
  It is asked again when the emailed code is verified, so closing registration
  also stops sign-ups already in flight; a refusal there looks like a wrong
  code and removes the pending code.
- **Only for new accounts.** An address that already has an account is
  recovery, and recovery never calls the hook, whatever it would answer.
- **It replaces the static setting.** When a policy is set it alone decides:
  `REGISTRATION` and `BOOTSTRAP_CODE` are not consulted for new accounts (the
  startup checks on them still run). The invitation code is ignored when a
  policy is set: the policy never receives it and the sign-in page does not
  show the field. With no policy, everything above is unchanged.
- **Deny.** Return `false` and a message. The request answers
  `403 {"error":"registration_refused","error_description":"<message>"}`, and
  the sign-in page shows the message. An empty message becomes
  "Registration is currently closed.". Nothing is stored or mailed.
- **Error.** Fails closed: the same 403 with a generic "unavailable" message;
  the error is logged and never shown.

**This is the one place Portiko says no out loud.** The static modes answer
`202 code_sent` for everyone, so a caller cannot tell a new address from a
registered one. A policy refusal is a 403 that only a new address can receive,
so while the policy denies, `register/start` reveals which addresses have no
account. That is the price of telling the person why; it is bounded by the
per-address and per-IP rate limits. A site that cannot accept it should keep the
static modes, or answer allow and refuse later in its own sign-in handling.
A site that already publishes "registration is closed" loses nothing more than
the existence of one address per rate-limited request.

## Enrolling the first account

1. Deploy with `REGISTRATION=code` and a long `BOOTSTRAP_CODE`.
2. Open `/signin`, choose email, and enter your address and the invitation code.
3. Enter the emailed code and create a passkey. Add a second passkey straight
   away ([Recovery](recovery.md)).
4. To let others join, give them the code. To stop, set `REGISTRATION=closed`
   and restart; existing accounts are unaffected.

The sign-in page shows the invitation-code field only in `code` mode. A
deployment with its own `TEMPLATE_DIR` must add the field itself, as
`bootstrap_code` in the `register/start` body, or nobody can create an account.
