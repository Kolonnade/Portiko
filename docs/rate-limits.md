# Rate limits, and the address a request comes from

A six-digit code has a million values. Guessing is only hard if guessing is
bounded, so the limits below are part of what makes the one-time code safe at
all, not a capacity measure.

## What is limited

| Endpoint | Per address | Per IP |
|---|---|---|
| `POST /accounts/v1/register/start` — ask for a code | 5 / hour | 30 / hour |
| `POST /accounts/v1/register/verify` — submit a code | the guess budget below | 60 / hour |
| `GET /accounts/v1/login/start` | 60 / hour | 120 / hour |
| `POST /accounts/v1/login/finish` | — | 120 / hour |
| `POST /oauth/token` | — | 3600 / hour |
| `POST /accounts/v1/emails/add` — add an address | 5 / hour | 30 / hour |
| `POST /accounts/v1/emails/verify` | the guess budget below | 60 / hour |

Plus the one that matters most:

**Ten code guesses per address per hour, across every code that address has been
sent.** The per-code counter of five is still there, but it was never the binding
constraint: asking for another code created another row with another five guesses,
so five-per-code plus unlimited codes was the whole code space in about 200,000
requests. The per-address counter does not live in the pending rows, so it is not
reset by a new code, by consuming one, or by one expiring.

Once that budget is gone, even the correct code is refused until the window turns
over. That is the point.

The numbers are set for a deployment serving households, not a public sign-up
funnel. A family behind one address is the case that must not be locked out, so
the per-IP figures are deliberately loose and the per-address figures — the ones
that bound an attack on one account — are tight. The token endpoint is the loosest
of all: its callers are relying parties, not browsers, they arrive from a handful
of addresses, and a limit tight enough to be interesting there would take a site
down under ordinary load.

## What a limited request gets

`429` with a `Retry-After` in seconds, and this body:

```json
{"error":"rate_limited"}
```

The same body for every cause and every address. Which budget ran out — the
caller's address or the email it named — and whether that email has an account are
all invisible from the outside; the server log names the budget instead. An
address with an account and an address without one are refused identically,
because the difference would be an account-enumeration oracle (see
[opinions.md](opinions.md)).

## Where the limits live

Two layers, because they catch different things.

- **Per-IP, in process** (`sethvargo/go-limiter`). A flood from one address lands
  on one replica and is cheapest to stop there, and a limiter that needs a
  database round trip per request is itself a way to exhaust the database.
- **Per-address, in Postgres.** This is the one that bounds what can be done to a
  single account, and an attacker spreading requests across replicas would
  otherwise get each replica's budget. Fixed windows, so one row per
  bucket-and-subject rather than one per event; the worst a fixed window allows is
  twice the limit across a boundary, which for ten guesses an hour is twenty.

The subject of a per-address counter is stored hashed. The table would otherwise
be a list of every address that has asked for a code, sitting in the same database
as the accounts.

## `TRUSTED_PROXIES` — set this

```
TRUSTED_PROXIES=127.0.0.1,::1
```

A comma-separated list of addresses or CIDRs. `X-Forwarded-For` is believed **only
when the connection itself comes from one of them**; otherwise the connection's own
address is used, and with the list empty — the default — the header is ignored
entirely.

That default is the safe one but it is not the right one behind a proxy, and the
cost of leaving it unset is an outage rather than a hole: every request then
appears to come from the proxy's loopback address, so one per-IP budget is shared
by everybody using the deployment. The provider logs a warning at startup when the
list is empty and `DEV_INSECURE` is not set.

Trusting the header unconditionally would be the opposite mistake. It is written
by the client until a proxy appends to it, so a caller could claim any address it
liked: every per-IP limit becomes decoration and the audit trail fills with
addresses of the attacker's choosing.

The header is read right to left. A proxy appends the address it saw, so the
rightmost entry is the one added closest to this service and the only one the
client could not write; entries that are themselves trusted proxies are skipped,
so a chain of two or three works. An entry that is not an IP address at all means
the header cannot be reasoned about, and the connection's address is used instead.

## `RATE_LIMIT_EXEMPT` — test deployments only

```
RATE_LIMIT_EXEMPT=198.51.100.7
```

A comma-separated list of addresses or CIDRs whose requests skip every endpoint
limit in the table above, per-IP and per-address alike. It exists so an
end-to-end suite run several times an hour from one machine is not refused;
without it the only way out was restarting the service to empty the in-process
buckets.

- The address checked is the one `TRUSTED_PROXIES` resolves, so a client cannot
  exempt itself by sending `X-Forwarded-For`, and a trusted proxy is not exempt
  just because it relays exempt traffic.
- A prefix covering a whole address family (`0.0.0.0/0`, `::/0`) is refused at
  start-up. There is no switch that turns the limits off for everyone.
- The ten-guesses-per-address code budget is not an endpoint limit and still
  applies. Use a fresh address per run.
- When set, the provider logs a warning at start-up listing the addresses:

  ```
  level=WARN msg="RATE_LIMIT_EXEMPT is set: requests from these addresses skip the endpoint rate limits. Never set this on a production deployment." addresses=198.51.100.7/32
  ```

Never set it on production. Before and after each production deploy, check that
the environment file has no `RATE_LIMIT_EXEMPT` line and the start-up log has no
`RATE_LIMIT_EXEMPT is set` warning.
