# Sign-in events

A deployment can watch its sign-in page as a funnel: how many people see it, submit an address, get a code, verify it, create or use a passkey, and land back on the site. Set `Options.OnSignInEvent` and Portiko calls it once for each stage of each attempt. Leave it nil, the default, and nothing is reported.

```go
p, err := provider.New(ctx, cfg, provider.Options{
	OnSignInEvent: func(ctx context.Context, e provider.SignInEvent) {
		events <- e // hand it off; do not block
	},
})
```

## What the hook gets

`SignInEvent` carries `FlowID`, `ClientID`, `Stage`, `Outcome`, `Reason`, `UserAgent`, `Source` and `Time`. It never carries an email address, an IP address or a user ID.

- **FlowID** ties one attempt's stages together. It is the authorization request ID when a site sent the person, otherwise a random ID the sign-in page mints for each page view.
- **ClientID** is the site being signed in to, when there is one.
- **Outcome** is `ok`, `fail` (with a `Reason`) or `abandon` (the person dismissed the browser's passkey dialog).
- **Source** is `server` for what the provider saw itself and `browser` for what the sign-in page reported.

The hook runs synchronously on the request goroutine, so a slow hook slows sign-in: queue the event and return. A panic in it is logged and swallowed. Portiko stores nothing; the hook is the only sink.

## Stages

| Stage | Fires when | Fail reasons |
|---|---|---|
| `page_shown` | the sign-in page is rendered, or `/login` is reached with a lapsed request | `request_expired` |
| `email_submitted` | `register/start` receives a body | `bad_request` |
| `code_sent` | the address was accepted. This is *accepted*, not *delivered*: an address quietly declined (an existing account, a missing invitation code) still reads `ok`, so nothing here distinguishes them | `registration_refused`, `send_error`, `rate_limited` |
| `code_verified` | `register/verify` checks the code | `code_wrong`, `code_expired`, `too_many_attempts`, `code_unknown`, `code_rejected`, `rate_limited` |
| `passkey_create_started` | the creation options are sent, right after a good code | — |
| `passkey_create_finished` | `register/finish` answers, or the page reports the dialog failed | `parse_error`, `verify_failed`, `too_many_accounts`, `server_error`, or the browser's `DOMException` name |
| `passkey_signin_started` | `login/start` answers | `start_failed`, `rate_limited` |
| `passkey_signin_finished` | `login/finish` answers, or the page reports the dialog failed | as for `passkey_create_finished`, plus `rate_limited` |
| `redirected` | the person is sent back to a site | `account_mismatch`, `complete_failed`, or the OpenID Connect error (`login_required`, `access_denied`, …) |

Reasons reach only the hook. The client still gets the same generic failure for every cause, so a wrong code and an unknown address remain indistinguishable from outside.

Portiko's sign-in asks for no name, so there is no name stage. Abandonment is never reported by the server: infer it from an attempt whose later stages never arrive. The one exception is a passkey dialog, which only the browser sees; a `NotAllowedError` or `AbortError` is reported as `abandon`, any other error as `fail`.

## The browser report

The built-in page posts a dismissed or failed passkey dialog to the provider. A replacement page under `TEMPLATE_DIR` can do the same:

- `POST {Base}/signin/event?authRequestID=…` or `?flow=…`, from the provider's own origin, with JSON `{"stage": "passkey_create_finished" | "passkey_signin_finished", "error": "<DOMException name>"}`.
- The answer is always `204` (and `429` when rate limited, 120 an hour per IP). A cross-origin request gets `403`. An unknown stage is dropped; an error name that is not 1–40 letters becomes `UnknownError`. `ok` outcomes come only from the server.
- The template data carries `FlowID` (the flow to send) and `SignInEvents` (whether a hook is set; send nothing when false). The ceremony requests should carry the same `?authRequestID=` or `?flow=` query so the server's stages share the flow. A template that omits them keeps working; its server stages just have an empty flow.
