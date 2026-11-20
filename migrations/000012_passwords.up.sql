-- The opt-in password credential (PASSWORDS=allow): at most one per account,
-- alongside or instead of its passkeys. Passkeys stay the recommended
-- credential; see docs/opinions.md for why this exists at all.
CREATE TABLE passwords (
    user_id          BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- Argon2id in PHC form ($argon2id$v=19$m=…,t=…,p=…$salt$hash). The
    -- parameters travel with the hash, so they can be raised later.
    hash             TEXT NOT NULL,
    -- Set when the password came from recovery (an emailed code), as for a
    -- passkey (migration 000011): until then its sessions may not take the
    -- account's other ways in away.
    restricted_until TIMESTAMPTZ,
    -- Per-account backoff. Consecutive failures since the last success; past
    -- a few, each attempt waits until locked_until.
    failed_attempts  INT NOT NULL DEFAULT 0,
    locked_until     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at     TIMESTAMPTZ
);
