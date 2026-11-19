# How long a sign-in may take

A site sends a person to the provider with an authorization request. A first
sign-up has to fit inside that request's life: type an address, find the code
(perhaps in spam, perhaps after an interruption), enter it, create a passkey.

## The provider's request

- A request lives **30 minutes without activity** (`store.AuthRequestTTL`).
  Every request to the sign-in page or a sign-in endpoint that names it
  (`?authRequestID=`) starts the 30 minutes again.
- However active it stays, it ends **2 hours** after the site sent the person
  (`store.AuthRequestMaxLife`).
- The request itself guards nothing a person could guess. The code (10
  minutes, 15 for recovery), the passkey challenge (5 minutes) and the rate
  limits bound those parts.

## When it runs out anyway

An expired request is kept for a day (`store.ExpiredAuthRequestRetention`).
While it is, a person who comes back to it, whether by finishing the
ceremony, reloading the sign-in page or following `/login?authRequestID=`, is
sent to the site's `redirect_uri` with

```
error=login_required&error_description=…&state=<the site's state>
```

so the site can start its sign-in again with whatever it remembered about where
the person was going. The account they just made, or the sign-in they just
did, is not lost: the provider session exists, so the new request usually
completes without asking anything. A request whose site was removed, or whose
redirect URI is no longer registered, and one past the day, get the "This
sign-in link has expired" page instead.

## The site's side

`rp` keeps its sign-in state (state, nonce, PKCE verifier and the `return_to`
path) in the `portiko_rp_flow` cookie for 2 hours, matching the provider's cap.

When the callback receives `error=login_required` with a valid state, `rp`
starts the sign-in again **once**, with the same `return_to` and `login_hint`.
It does not repeat `prompt`: `login` or `create` would ask someone who has just
signed in, or just made their account, to do it again. A second
`login_required` on the restarted sign-in fails as any other error does, so a
misbehaving provider cannot loop the browser.

A site that does not use `rp` should do the same: treat `login_required` on its
callback as "start again", keeping its own idea of where the person was going.
