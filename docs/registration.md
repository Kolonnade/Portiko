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
