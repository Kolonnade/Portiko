-- Rolling back removes every password. An account that had only a password is
-- left with no credential and must recover with its email address.
DROP TABLE passwords;
