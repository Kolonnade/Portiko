-- An account can hold several verified emails (identifiers already allows it);
-- this adds what changing them needs.

-- An address being added to an account that already exists, awaiting the code
-- sent to it. Its own table, not pending_registrations: a row here belongs to
-- an account, and the registration path looks rows up by address alone, so a
-- shared table would let one flow's code be redeemed by the other.
CREATE TABLE pending_emails (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email      TEXT NOT NULL,            -- normalized
    code       TEXT NOT NULL,            -- the 6-digit OTP
    attempts   INT NOT NULL DEFAULT 0,   -- guesses at this code
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_pending_emails_user ON pending_emails (user_id, email);
CREATE INDEX idx_pending_emails_expires ON pending_emails (expires_at);

-- At most one primary address of each kind per account. Swapping the primary
-- clears the old one before setting the new one, inside one transaction.
CREATE UNIQUE INDEX idx_identifiers_one_primary ON identifiers (user_id, kind) WHERE is_primary;
