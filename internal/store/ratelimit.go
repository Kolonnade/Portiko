package store

import (
	"context"
	"time"
)

// Rate-limit buckets. A bucket names what is being limited; the subject names
// whose budget it comes out of.
const (
	// RateBucketCodeGuess counts guesses at a one-time code, per address.
	RateBucketCodeGuess = "code.guess"
	// RateBucketCodeRequest counts one-time codes asked for, per address.
	RateBucketCodeRequest = "code.request"
)

// Decision is the answer to "may this happen?".
type Decision struct {
	OK bool
	// RetryAfter is how long until the window ends. It is what the 429's
	// Retry-After header carries, so a well-behaved client waits instead of
	// retrying immediately and making the problem worse.
	RetryAfter time.Duration
	// Count is how many events this window has now seen, the refused one included.
	Count int
}

// Allow records one event against a subject's budget and reports whether it is
// within limit.
//
// It counts first and asks afterwards, deliberately: an event that is refused
// still consumed a slot. Otherwise the refusals themselves are free, and an
// attacker who has exhausted a budget simply keeps going.
//
// A database failure is returned, not swallowed. A limiter that fails open is a
// limiter an attacker can remove by making the database unhappy, and the caller
// here would rather refuse the request.
func (d *DB) Allow(ctx context.Context, bucket, subject string, limit int, window time.Duration) (Decision, error) {
	var count int
	var expires time.Time
	// The window boundary is computed from the clock in the database, not in this
	// process, so replicas with slightly different clocks share one window rather
	// than each keeping its own.
	err := d.pool.QueryRow(ctx,
		`INSERT INTO rate_counters (bucket, subject, expires_at, count)
		 VALUES ($1, $2,
		         to_timestamp((floor(extract(epoch from now()) / $3) + 1) * $3), 1)
		 ON CONFLICT (bucket, subject, expires_at)
		   DO UPDATE SET count = rate_counters.count + 1
		 RETURNING count, expires_at`,
		bucket, subject, window.Seconds()).Scan(&count, &expires)
	if err != nil {
		return Decision{}, err
	}
	retry := time.Until(expires)
	if retry < time.Second {
		retry = time.Second
	}
	return Decision{OK: count <= limit, RetryAfter: retry, Count: count}, nil
}

// sweepRateCounters removes windows that have ended.
func (d *DB) sweepRateCounters(ctx context.Context) (int64, error) {
	tag, err := d.pool.Exec(ctx, `DELETE FROM rate_counters WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
