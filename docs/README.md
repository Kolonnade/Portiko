# Portiko documentation

Design notes written ahead of the code, so the implementation has something to be checked against.

| Document | What it covers |
|---|---|
| [opinions.md](opinions.md) | The positions that shape the API, and what a contribution will be measured against |
| [multiple-accounts.md](multiple-accounts.md) | Several accounts signed in at once: the session model, choosing an account at the provider, and how server-rendered sites, single-page applications and native apps each say which account they mean |
| [recovery.md](recovery.md) | What happens when someone loses their passkey, their email, or both: the ladder from a second passkey down to the operator, and the rules every path follows |

More will land as the code does: the protocol specification, a self-hosting guide, the threat model, and a guide to signing in across sites on different domains.
