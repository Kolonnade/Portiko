-- Best-effort reversal. Session cookies cannot be restored from their hashes, so
-- every browser is signed out.

ALTER TABLE oauth_clients
    DROP COLUMN application_type,
    DROP COLUMN post_logout_redirect_uris,
    DROP COLUMN allowed_scopes;

DROP INDEX IF EXISTS idx_refresh_tokens_family;
ALTER TABLE refresh_tokens
    DROP COLUMN rotated_at,
    DROP COLUMN amr,
    DROP COLUMN auth_time,
    DROP COLUMN family_id;

CREATE TABLE authorization_codes (
    id             BIGSERIAL PRIMARY KEY,
    code_hash      TEXT UNIQUE NOT NULL,
    client_id      TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    nonce          TEXT,
    scope          TEXT NOT NULL DEFAULT 'openid',
    sid            TEXT,
    expires_at     TIMESTAMPTZ NOT NULL,
    consumed_at    TIMESTAMPTZ
);
CREATE INDEX idx_auth_codes_expires ON authorization_codes (expires_at);

DROP TABLE auth_requests;

DELETE FROM sso_sessions;
DROP INDEX IF EXISTS idx_sso_sessions_browser_ordinal;
DROP INDEX IF EXISTS idx_sso_sessions_browser_user;
ALTER TABLE sso_sessions
    ADD COLUMN token TEXT UNIQUE NOT NULL,
    DROP CONSTRAINT sso_sessions_browser_fk,
    DROP COLUMN amr,
    DROP COLUMN authenticated_at,
    DROP COLUMN is_default,
    DROP COLUMN ordinal,
    DROP COLUMN browser_hash;

DROP TABLE browsers;
