-- Dropping the counters forgets every window in progress, so the limits start
-- again from zero. That is acceptable for a rollback and is worth knowing: an
-- attack in progress gets a fresh budget.
DROP TABLE rate_counters;
