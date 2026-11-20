# Test mail domains

An end-to-end test has to sign up, and signing up starts with a six-digit code
sent by email. `TEST_MAIL_DOMAINS` lets a test deployment write those codes to
the log for a few domains, while every other address is still emailed as usual.

```
TEST_MAIL_DOMAINS=example.test
```

A comma-separated list. For an address whose domain (the text after the last
`@`, lowercased) exactly matches a listed one, the sign-in code and the
new-passkey notice are written to the log instead of being sent. A subdomain of
a listed domain is not matched; list it too if you need it.

## Reserved names only

The provider refuses to start if any listed domain is not one reserved for
testing by RFC 2606 and RFC 6761:

- any name ending in `.test`, `.invalid` or `.example`
- `example.com`, `example.net`, `example.org`, and their subdomains

Nobody can own a mailbox under these names, so the setting can never capture a
real person's code, even if it is set somewhere it should not be. `localhost`,
wildcards and any other domain are refused.

## At start-up

When the setting is in effect the provider logs a warning listing the domains:

```
level=WARN msg="TEST_MAIL_DOMAINS is set: sign-in codes for these domains are written to the log, not emailed. Never set this on a production deployment." domains=example.test
```

## Reading a code from a test

Each captured code is one log line:

```
level=WARN msg="test mail domain; not sending, logging instead" to=alice@example.test code=123456
```

A harness finds the latest line with `to=<address>` and takes `code=(\d{6})`
from it. Use a fresh address per run.

A test that cannot drive a passkey can, on a deployment with `PASSWORDS=allow`,
choose a password after the code and sign in with it later, all with plain HTTP
requests. [Passwords](passwords.md#a-scripted-client) lists the requests.

The [rate limits](rate-limits.md) still apply to test addresses: five codes per
address per hour, ten guesses per address per hour. A test deployment whose suite
runs often from one machine can list that machine in `RATE_LIMIT_EXEMPT` to skip
the endpoint limits; the guess budget still applies.

## Never on production

Before and after each production deploy, check that the environment file has no
`TEST_MAIL_DOMAINS` line and that the start-up log has no `TEST_MAIL_DOMAINS is
set` warning.
