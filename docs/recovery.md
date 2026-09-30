# Recovery

Recovery is a way to add a credential to an account you do not currently control. That is its purpose and also its danger: **an account is only as secure as its easiest recovery path**, no matter how good the passkeys are.

In a passkey-only system, three situations account for nearly all of it:

- *"I have a new phone."* Usually not recovery at all — synced passkeys follow the person through their provider's own account.
- *"I lost my passkeys."* The email still works, so this is the ordinary path.
- *"I lost everything — passkeys and the email itself."* This is the one that needs an answer decided in advance, because the alternative is inventing one under pressure for a person who is upset.

## The ladder

Portiko's position, in the order a deployment should rely on them.

### 1. A second passkey (the real answer)

Prompt for a second credential right after the first enrollment, and keep prompting while an account has only one. A passkey on a second device, a second provider, or a hardware key removes the single point of failure entirely and costs nothing to operate.

Everything below this line exists because people will not do it.

### 2. Recovery codes

Ten single-use codes, generated at enrollment, shown exactly once, stored hashed like any other secret. Each one can be spent to run the recovery ceremony.

Offline, unphishable, no new channel to attack, and no dependency on a mail provider. Regenerating the set invalidates every outstanding code, and spending one leaves the others alone. Show the remaining count in account settings, because a person with two left should know.

### 3. A verified identifier

Any **verified** email or phone on the account can start the recovery ceremony. Several identifiers are better than one: the second email is what saves most people in practice.

A phone is a factor, not a door. Recovery that can be completed by SMS alone is recovery by SIM swap, so a phone should either be paired with something else or limited to lower-risk steps.

### 4. Trusted people (when the identifier is gone too)

The answer to *"I lost everything"*, and the one that fits a community platform best: **the people who know you are better identity proofers than any document**. A neighbor recognizes you; a scanned license only proves someone holds a scanned license.

How it works:

1. **Nomination.** A person names two or more trusted accounts. Each nominee must **accept** — otherwise anyone could list strangers and manufacture a quorum later.
2. **Cooling period on the list itself.** Adding or replacing a trusted account takes effect only after a delay, and notifies every identifier. Without this, an attacker with a few minutes of access appoints themselves and a friend, then transfers the account immediately.
3. **Request.** The locked-out person starts a transfer of the account to a new email address, from anywhere.
4. **Vouching.** Each trusted account approves by signing in with **their own passkey** and confirming. The approval is therefore phishing-resistant, and it is a deliberate act by a person who is expected to have checked in the real world that this is really you.
5. **The veto window.** Reaching the threshold does not complete the transfer. It starts a hold — measured in days — and sends notice to the original email, every other identifier, and every live session: *a transfer was requested; press here to stop it.* Any of those, or any trusted account withdrawing approval, cancels it outright.
6. **Completion.** If nobody objects — which is what a genuinely lost mailbox looks like — the transfer completes: the new address becomes the identifier, a new passkey is enrolled, and the old credentials, identifiers and sessions are revoked. Everyone is told, including the trusted accounts, so the people who vouched know it finished.

The window is doing the real work. A legitimate owner who still reads their email stops the transfer in one click; a genuinely lost mailbox stays silent and the transfer completes on its own.

Bounds that matter:

- **Threshold and set size are configurable**, with a minimum of two approvals. Three nominees with a threshold of two survives one trusted person losing their own account.
- **One active request at a time**, rate-limited, so this cannot be used to bombard someone's inbox.
- **Approvals expire.** A stale approval collected weeks ago should not count toward a later request.
- **Consider a reclaim window.** For a period after completion, presenting one of the old credentials freezes the account and alerts everyone rather than being silently rejected — the safety net for an owner who was simply away during the hold.
- **Collusion is the residual risk.** Two people who both know you and both decide to take your account can. That is the same trust you extend by giving someone a house key, and it is why the set is chosen by the person and changes slowly.

This doubles as a legacy path: the same mechanism lets a family recover an account when its holder has died, without a separate feature.

### 5. The recovery ceremony itself

Whatever gates it — a code, a link, a quorum of trusted people — the ceremony that follows is the same, and it is deliberately narrow:

- It is **a registration ceremony that attaches a credential to an existing subject**.
- It creates no account and changes no other state.
- It uses a longer window than enrollment (15 minutes against 5), because it starts from a message read on another device.
- It is **never gated by whether registration is open.** A closed deployment that gates recovery locks its own users out permanently, and leaves the first administrator unable to enroll at all.
- On its own it does **not** revoke existing credentials. The legitimate holder may still have a working passkey, and automatic revocation hands an attacker a way to lock them out. The trusted-people transfer is the exception, because revoking is the point of a transfer and the veto window has already run.

### 6. The operator, for self-hosted deployments

Whoever runs the server has database access, so they can always restore an account. That is a real escape hatch and should be written down rather than left implicit: **the operator of a deployment can take over any account on it.** Give them a command that does it deliberately and writes an audit row, rather than leaving them to hand-edit rows at 1am.

## Not in the ladder

| Approach | Why not |
|---|---|
| **Government identity** — Login.gov, a state DMV, a mobile driver's license | Rejected on principle, not on feasibility. This platform exists so that a community can host its own data and protect it. An account that a government can recover is an account a bad actor inside that government can take, which undermines the whole proposition — and it would bind a self-hostable project to one country's infrastructure, exclude everyone without an ID or a wallet phone, and require holding identity-document data to match against later. The people who know you are the better proofers, and they are already here. |
| Security questions | The answers are public records or forgotten; they weaken every account that has them |
| SMS as the only path | SIM swap is routine and cheap |
| Unbounded support-mediated recovery | It becomes the attack, and it does not scale to a self-hosted deployment with no support desk |
| Secret-splitting schemes for social recovery | Unnecessary machinery here. The provider already holds the account; an approval is an authenticated action by a person, not a share of a key. |
| No recovery at all | Defensible for a wallet. Cruel for a family photo album. |

## Rules for every path

- **Enumeration-resistant.** Starting recovery for an address that has no account looks exactly like starting one that does.
- **Bounded.** Attempts are counted per account across codes and messages, not per message, or requesting a fresh code resets the guess budget. Per-address and per-IP limits apply on top.
- **Loud.** A recovery attempt notifies every verified identifier and every live session. A completed one does the same and writes an audit row. A takeover people can see is a takeover they can report.
- **Held when the ground is fresh.** A hold — announced to every identifier — applies when recovery arrives through an identifier that was added or changed recently, which is the shape of an account takeover. It does **not** apply on the ordinary path of a long-verified address, because delaying that punishes the person you are trying to help. The trusted-people path always holds, by design.
- **Narrow.** Recovery adds a credential. Only the trusted-people transfer changes identifiers, and it says so in every message it sends.
- **The last credential is protected.** An account cannot delete its only passkey unless recovery codes or trusted people exist, because with no password to fall back on that is not an inconvenience, it is a permanently unreachable account.

## What breaks without each rule

| Skipped | Result |
|---|---|
| A second credential prompted at enrollment | Every account is one lost device from the recovery path |
| Attempts bounded per account | A six-digit code is guessable inside its own lifetime |
| Notifications | A takeover is silent, and nobody reports it |
| The veto window on a transfer | Two people can take an account with no chance for its owner to object |
| A cooling period on the trusted list | An attacker with brief access appoints themselves and transfers immediately |
| Nominees having to accept | A quorum can be manufactured from people who never agreed |
| Hold on recently changed identifiers | The standard takeover works: change the address, recover through it |
| Not auto-revoking on ordinary recovery | An attacker who reaches recovery can also lock the owner out |
| The last-credential guard | Accounts delete themselves by accident |

## What a deployment chooses

Portiko ships the ceremony, the codes, the trusted-people flow, the limits, the notifications and the audit trail. A deployment decides the rest:

- whether recovery codes and trusted people are enabled (both should be)
- the threshold, the set size, and the length of the veto and cooling windows
- which identifier kinds count, and how they are verified
- who may run the operator command, and how that is logged
- the wording of every message, since these are the most-read emails the system sends

## Recovery is not the only survival

Losing an account need not mean losing what you did with it. Where membership in a group is local to that group — as it is in the platform Portiko was built for — a local administrator who knows the person can move their membership and history to a new account, independently of anything here. That is a community-layer feature rather than an identity-layer one, and it means the worst case is a lost credential rather than a lost life.
