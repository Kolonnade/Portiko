# Several signed-in accounts

One person, several accounts, signed in at once — and each site or app showing whichever one they chose for it. This is the model people already know from Google, and it shapes the session design, so it is worth understanding before anything else.

## The rule everything follows

> **When more than one account is signed in, the server never infers which one a request means from the cookie alone. The client says so explicitly, and an ambiguous request is refused or sent to the chooser — never guessed.**

Cookies are scoped to an origin, not to a tab. A browser sends the same jar to every tab of `example.com`, so the cookie can only answer *which browser is this* and *which accounts are signed in on it*. Something request-scoped has to answer *which of them is this page*.

Everything below is a consequence of that one sentence.

## What the server holds

```
cookie  →  an opaque browser identifier, and nothing else

sessions (one row per browser and account)
  browser_id    the cookie's value, stored hashed
  user_id       the account
  sid           the public per-account session id, sent to sites in tokens
  ordinal       0, 1, 2 … assigned in sign-in order
  is_default    exactly one per browser
```

- The cookie never changes as accounts are added or removed, so two tabs adding accounts at once cannot race.
- `sid` stays per browser *and* account, which is what makes back-channel logout able to end one account's sessions without touching the others.
- **Ordinals are never reused while the browser's session set lives.** Removing account 1 leaves 0 and 2 where they are. A stale link carrying `1` must never land on somebody else's account.
- Numbers are a handle, never an identity. They are resolved to a subject on the server on every request. Nothing is ever keyed on the number.

## Choosing an account at the provider

Portiko uses the standard OpenID Connect parameters rather than inventing any:

| Request | Result |
|---|---|
| No hint, one session | That account |
| No hint, several sessions | The chooser |
| `login_hint` matching a signed-in account | That account, no interface |
| `id_token_hint` | That subject's session, or re-authentication of it |
| `prompt=select_account` | Always the chooser — this is what a site's "switch account" button sends |
| `prompt=none`, several sessions, no hint | The `account_selection_required` error |
| No session at all | The passkey ceremony |

A site switching accounts therefore costs one redirect and no passkey prompt, because the account is already signed in at the provider.

## How a client says which account

Three shapes, depending on what you are building. Pick one per application and be consistent.

### Server-rendered pages: put it in the path

```
/u/0/albums/3
```

- A bare URL (`/`) resolves the default account and **redirects** to its prefixed URL, so the account is always in the address bar and never implied.
- The prefix is on API routes too (`/u/1/api/items`), or a page open as account 1 will read account 0's data.
- An unknown or removed number shows the chooser.

This is the Google model, and it is the right default: bookmarks, shared links, browser history and two tabs open as different accounts all work with no extra machinery.

### Single-page applications: per tab, in the fragment, on every request

A single-page app can keep the account out of the server-visible URL, provided it does three things:

1. **Remember it per tab, durably.** `sessionStorage` — scoped to the tab and surviving a reload. **Not** `localStorage`, which is shared across tabs and makes two tabs fight over one account. Not a variable alone, which is gone after a refresh.
2. **Put it in the fragment for deep links:** `#/u/1/album/3`. The fragment is never sent to the server, so the application reads it and picks the account itself. Without this, a shared link or a new tab opens as the default account and shows the wrong data.
3. **Send it explicitly on every request:** `X-Account: 1`, or the account's own bearer token. A custom header is a useful side effect here: it forces a CORS preflight, so a cross-site form post cannot forge it.

Two further notes:

- Prefer the History API over hash routing where you can. You get real paths, ordinary back-button behavior, and the option of `/u/1/` for free; the cost is a rewrite rule that serves the application for any path.
- The OAuth callback is a top-level navigation, so it cannot read the fragment. Carry the intended account and the return target in the `state` parameter, then redirect to a URL that includes the fragment.

### Native apps: by subject, not by URL

An app addresses an account by its subject and holds a token per account, so the question does not arise. The device session and its device secret are per account, which is what lets a family of apps share a sign-in while each one chooses which account it is showing.

## Rules that hold whatever the client

- **A stale selector shows the chooser.** Never a different account. This is a safety property, not a convenience.
- **Per-account responses are `Cache-Control: private, no-store`,** and no shared cache is keyed on a URL that omits the account.
- **Local rows are keyed on the subject,** so two accounts at one site never share data — including in caches, drafts and background jobs.
- **Signing out is per account by default:** that `sid`, its refresh tokens, and a back-channel logout token to the clients that held them. "Everything in this browser" and "everywhere" are separate, deliberate actions.
- **A site is never signed in to an account the person did not choose for it.** Holding three accounts at the provider does not sign you in to three accounts everywhere.

## What goes wrong without each rule

| Skipped | Symptom |
|---|---|
| Explicit selector; server falls back to a cookie | Two tabs silently show the same account; switching in one flips the other |
| Selector on API calls as well as pages | The page frame says account 1 while its data is account 0's |
| Never reusing numbers | A stale bookmark opens somebody else's mailbox after a removal |
| Chooser on a stale selector | The application quietly shows the wrong account, which the person may not notice |
| `private, no-store` on per-account responses | One account's page is served to another from a cache |
| Keying local data on the subject | Two accounts at one site bleed into each other |

## Deliberately not done

| Approach | Why not |
|---|---|
| A subdomain per account | Certificates, a session per host, and it breaks the single first-party origin the passkey and single sign-on design depends on |
| `?authuser=1` on every URL | Stripped by links, redirects and copy-paste |
| A request header alone | A top-level navigation cannot send one, which is exactly when a page loads cold |
| Path-scoped cookies | Still needs the path in the URL, and adds a mechanism that looks like isolation without being it |
| Several accounts in one token | Every token names exactly one subject. Always. |
| Linking or merging accounts | Two accounts stay two accounts |
