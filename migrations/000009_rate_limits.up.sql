-- Counters for the limits that must hold across replicas.
--
-- An in-process limiter is enough for per-IP limits: a flood from one address
-- hits one replica hard enough to be stopped there. It is NOT enough for a
-- per-address limit, which is the one that matters here — guessing a six-digit
-- code is cheap, and an attacker spreading guesses over two replicas gets twice
-- the budget from a limiter that lives in each process. So the counters that
-- bound what can be done to ONE ACCOUNT live in Postgres, like everything else
-- in flight (see docs/opinions.md).
--
-- Fixed windows, not sliding: a sliding window needs a row per event, and the
-- worst a fixed window allows is twice the limit across a boundary. For "ten
-- guesses an hour" that is twenty in the worst case and still nowhere near the
-- 200,000 it takes to cover the code space.
--
-- The subject is hashed, not the address itself. This table would otherwise be a
-- list of every address that has asked for a code, sitting next to the accounts
-- it describes, and the counter needs only equality.
CREATE TABLE rate_counters (
    bucket     TEXT NOT NULL,          -- what is limited, e.g. 'code.guess'
    subject    TEXT NOT NULL,          -- hashed address, or an IP
    expires_at TIMESTAMPTZ NOT NULL,   -- end of the window; part of the key, so a new window is a new row
    count      INT NOT NULL,
    PRIMARY KEY (bucket, subject, expires_at)
);

CREATE INDEX idx_rate_counters_expires ON rate_counters (expires_at);
