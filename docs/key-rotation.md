# Signing keys: at rest, and rotating them

Portiko signs every token with one ES256 key and publishes the public half in its
key set. Two things follow from that, and both are operator work.

## How the private key is stored

The private key is encrypted in the database with AES-256-GCM under the
deployment's `CRYPTO_KEY` — the same 32-byte secret that already encrypts
authorization codes. The key id is authenticated alongside the ciphertext, so one
row's encrypted key cannot be moved onto another row's id.

`CRYPTO_KEY` lives in the service environment and never in the database, which is
the whole point: a database backup is no longer a kit for forging tokens for
every site that trusts this provider.

**`CRYPTO_KEY` is now key material, not a convenience.** Losing it means losing
every signing key, which means every relying party must re-fetch a key set that
no longer contains anything it has seen. Back it up where you back up nothing
else, and never rotate it without first running `unseal-keys` under the old value
and `seal-keys` under the new one.

### Why not AWS KMS

A KMS data key, or signing directly with a KMS `ECC_NIST_P256` key, would both
put one cloud vendor in the trust path of a provider that is meant to be
self-hostable — the same reason mail goes out over SMTP rather than a vendor SDK
(see [opinions.md](opinions.md)). `CRYPTO_KEY` already satisfies the requirement
that matters: the key that decrypts the signing keys is held outside the
database. A deployment that wants KMS can hold `CRYPTO_KEY` in it.

### The one-off, on an existing deployment

Migration 8 renames `signing_keys.private_key_pem` to `private_key`, because its
contents are no longer PEM. SQL has no access to `CRYPTO_KEY`, so the migration
cannot encrypt anything; `seal-keys` does, keeping every key's id so that tokens
already signed keep verifying.

```
migrate up            # the rename; invisible to any earlier release from here on
portiko seal-keys     # encrypts whatever is still plaintext; idempotent
<restart the service>
```

Startup refuses to run on a key it finds in the clear, naming `seal-keys` in the
error, unless `DEV_INSECURE=true`. So the order above is not optional: flipping
the release before sealing leaves a service that will not start.

`portiko keys` prints the ring and says `sealed` or `PLAINTEXT` per key, without
needing `CRYPTO_KEY`.

### Rolling back past migration 8

```
portiko unseal-keys   # with the NEW binary, which can still decrypt
migrate down
<flip back to the previous release>
```

`unseal-keys` writes the signing keys to the database in the clear. It exists for
this and nothing else.

## Rotating the signing key

Rotation is three steps with a wait between each, and the waits are the reason it
is not one command:

| Step | Wait before it | Why |
|---|---|---|
| `rotate-key` | — | Creates the next key, published but not signing. |
| `activate-key <kid>` | 15 minutes | A verifier caches the key set for up to that long. A key that signs the moment it exists signs tokens cached verifiers cannot check. |
| `retire-key <old kid>` | 15 minutes | The access token's lifetime. A key dropped from the key set before its tokens expire logs those holders out. |

The running service reads its key ring once, at startup, so **restart after each
step.** `rotate-key` prints the sequence with the waits filled in, and `keys`
shows where a rotation has got to.

```
portiko rotate-key          # → new kid, state pending
<restart>                   # the new key is now published
<wait 15 minutes>
portiko activate-key <new>  # new key signs; the old one moves to retiring
<restart>
<wait 15 minutes>
portiko retire-key <old>    # the old key leaves the key set
<restart>
```

A second rotation is refused while one is unfinished: two keys waiting in the
same phase is how you lose track of which one the service is about to sign with.

## Emergency rotation

A key you believe is compromised must stop signing now, and every token it signed
must stop being accepted. Both waits exist to protect relying parties, and both
are the wrong trade when the key is in someone else's hands.

```
portiko rotate-key
<restart>
portiko activate-key -force <new>   # skips the publish wait
<restart>
portiko retire-key -force <old>     # skips the expiry wait
<restart>
```

What `-force` costs, so you can tell people before they ask:

- `activate-key -force` — a verifier whose cached key set predates the new key
  rejects new tokens until it refetches, which is within a minute for a Portiko
  relying party and up to 15 minutes at worst.
- `retire-key -force` — every access token, ID token, logout token and security
  event signed by the old key stops verifying at once. Sites see signed-in users
  fail their next API call; they recover on the next refresh.

If `CRYPTO_KEY` itself is what leaked, the signing keys must be treated as
compromised too: rotate them as above, then change `CRYPTO_KEY` (`unseal-keys`
under the old value, update the environment, `seal-keys` under the new one) and
restart.
