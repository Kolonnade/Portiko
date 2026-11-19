-- Rolling back leaves every address an account already holds in place; only
-- additions still waiting for their code are lost.
DROP INDEX idx_identifiers_one_primary;
DROP TABLE pending_emails;
