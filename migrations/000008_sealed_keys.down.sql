-- Run `portiko unseal-keys` BEFORE this, while the new binary is still in place.
--
-- SQL cannot decrypt the keys: CRYPTO_KEY is in the service environment, not in
-- the database. Renaming the column back without unsealing first leaves sealed
-- bytes in a column called private_key_pem, which the previous release will read
-- as PEM and fail to parse — so the service will not start, and the keys are not
-- recoverable from here.
ALTER TABLE signing_keys RENAME COLUMN private_key TO private_key_pem;
