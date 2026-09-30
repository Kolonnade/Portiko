-- Portiko: the provider moves onto zitadel/oidc, and a browser can hold several
-- signed-in accounts.

-- ---------------------------------------------------------------- browsers
--
-- The session cookie now names a browser, not a session. A browser holds one
-- session per account, numbered from 0 in sign-in order. next_ordinal lives
-- here rather than being derived from the sessions, so a number is never
-- reused after an account is removed: a stale link carrying it must never land
-- on somebody else's account.
CREATE TABLE browsers (
    browser_hash TEXT PRIMARY KEY,            -- hash of the cookie value; the cookie itself is never stored
    next_ordinal INT NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Existing cookies keep working: an old session token becomes the identifier
-- of a browser holding exactly that one session, as account 0. The hash matches
-- the service's HashToken — unpadded base64url of SHA-256.
ALTER TABLE sso_sessions ADD COLUMN browser_hash TEXT;
UPDATE sso_sessions
   SET browser_hash = translate(rtrim(encode(sha256(convert_to(token, 'UTF8')), 'base64'), '='), '+/', '-_');

INSERT INTO browsers (browser_hash, next_ordinal, created_at)
SELECT browser_hash, 1, min(created_at) FROM sso_sessions GROUP BY browser_hash;

ALTER TABLE sso_sessions
    ALTER COLUMN browser_hash SET NOT NULL,
    ADD CONSTRAINT sso_sessions_browser_fk FOREIGN KEY (browser_hash) REFERENCES browsers (browser_hash) ON DELETE CASCADE,
    ADD COLUMN ordinal INT NOT NULL DEFAULT 0,
    ADD COLUMN is_default BOOLEAN NOT NULL DEFAULT TRUE,
    -- When the passkey ceremony behind this session happened. auth_time in every
    -- token comes from here, never from the time a token was issued.
    ADD COLUMN authenticated_at TIMESTAMPTZ,
    ADD COLUMN amr TEXT[] NOT NULL DEFAULT '{}';

UPDATE sso_sessions SET authenticated_at = created_at;
ALTER TABLE sso_sessions
    ALTER COLUMN authenticated_at SET NOT NULL,
    ALTER COLUMN authenticated_at SET DEFAULT now(),
    -- The cookie value was stored as-is. It is gone now; only its hash remains.
    DROP COLUMN token;

CREATE UNIQUE INDEX idx_sso_sessions_browser_user    ON sso_sessions (browser_hash, user_id);
CREATE UNIQUE INDEX idx_sso_sessions_browser_ordinal ON sso_sessions (browser_hash, ordinal);

-- ---------------------------------------------------------- auth requests
--
-- zitadel/oidc hands every authorization request to storage and resumes it by
-- id after sign-in, so requests live in Postgres like everything else in flight.
-- The code is recorded here too, hashed, which replaces the old
-- authorization_codes table.
CREATE TABLE auth_requests (
    id                    TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    redirect_uri          TEXT NOT NULL,
    response_type         TEXT NOT NULL,
    response_mode         TEXT NOT NULL DEFAULT '',
    scopes                TEXT[] NOT NULL,
    state                 TEXT NOT NULL DEFAULT '',
    nonce                 TEXT NOT NULL DEFAULT '',
    prompt                TEXT[] NOT NULL DEFAULT '{}',
    max_age               INT,
    login_hint            TEXT NOT NULL DEFAULT '',
    hint_subject          TEXT NOT NULL DEFAULT '',  -- from a verified id_token_hint
    code_challenge        TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    -- Filled in when a signed-in account completes the request.
    user_id               BIGINT REFERENCES users (id) ON DELETE CASCADE,
    sid                   TEXT,
    auth_time             TIMESTAMPTZ,
    amr                   TEXT[] NOT NULL DEFAULT '{}',
    done                  BOOLEAN NOT NULL DEFAULT FALSE,
    code_hash             TEXT UNIQUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at            TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_auth_requests_expires ON auth_requests (expires_at);

DROP TABLE authorization_codes;

-- ---------------------------------------------------------- refresh tokens
--
-- A family is every token descended from one grant. Presenting a token that was
-- already rotated away, outside a short grace window, revokes the whole family:
-- one party holding a copy is enough to assume it was stolen.
ALTER TABLE refresh_tokens
    ADD COLUMN family_id  TEXT,
    ADD COLUMN auth_time  TIMESTAMPTZ,
    ADD COLUMN amr        TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN rotated_at TIMESTAMPTZ;

UPDATE refresh_tokens SET family_id = token_hash, auth_time = created_at;
ALTER TABLE refresh_tokens
    ALTER COLUMN family_id SET NOT NULL,
    ALTER COLUMN auth_time SET NOT NULL;

CREATE INDEX idx_refresh_tokens_family ON refresh_tokens (family_id);

-- ---------------------------------------------------------------- clients
--
-- A client may be granted only the scopes it was registered for. Nothing a
-- relying party asks for beyond that is issued.
ALTER TABLE oauth_clients
    ADD COLUMN allowed_scopes TEXT[] NOT NULL DEFAULT '{openid,profile,offline_access}',
    ADD COLUMN post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN application_type TEXT NOT NULL DEFAULT 'web'
        CHECK (application_type IN ('web', 'native', 'user_agent'));
