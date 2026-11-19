-- A passkey enrolled through recovery (an emailed code, no existing passkey)
-- cannot, for a while, be used to take away the account's other ways in: its
-- sessions may not change the primary address, remove an address or revoke a
-- passkey until restricted_until. Holding an inbox on the account is enough to
-- recover it, so without this, whoever reads one backup address could lock the
-- holder out before the notices reached them.
ALTER TABLE passkey_credentials ADD COLUMN restricted_until TIMESTAMPTZ;

-- Copied from the credential at each sign-in, so a request is checked without
-- another query. A later sign-in with an older passkey clears it.
ALTER TABLE sso_sessions ADD COLUMN restricted_until TIMESTAMPTZ;
