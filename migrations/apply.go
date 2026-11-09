package migrations

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// lockKey is the advisory lock Apply holds, so replicas starting together take
// turns rather than racing to create the same table. Any constant works; this
// one is "portiko" in ASCII, truncated to fit a bigint.
const lockKey = 0x706f7274696b6f

// Apply brings the schema up to date and returns the version it ends at.
//
// It keeps its place in schema_migrations exactly as the golang-migrate CLI
// does (one row: version, dirty), so a deployment can move between the two
// in either direction. Each migration runs in its own transaction together
// with the version bump, so a failure leaves the schema at the last migration
// that succeeded and never marks it dirty. A schema the CLI left dirty is
// refused: a human has to look at it.
func Apply(ctx context.Context, conn *pgx.Conn) (int, error) {
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, int64(lockKey)); err != nil {
		return 0, fmt.Errorf("migrations: locking: %w", err)
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, int64(lockKey))

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations
		(version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)`); err != nil {
		return 0, fmt.Errorf("migrations: creating schema_migrations: %w", err)
	}
	current, dirty := 0, false
	err := conn.QueryRow(ctx, `SELECT version, dirty FROM schema_migrations LIMIT 1`).Scan(&current, &dirty)
	if err != nil && err != pgx.ErrNoRows {
		return 0, fmt.Errorf("migrations: reading the version: %w", err)
	}
	if dirty {
		return current, fmt.Errorf("migrations: version %d is marked dirty; fix the schema by hand, then run `migrate force`", current)
	}

	steps, err := upSteps()
	if err != nil {
		return current, err
	}
	for _, s := range steps {
		if s.version <= current {
			continue
		}
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, s.sql); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM schema_migrations`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, dirty) VALUES ($1, false)`, s.version)
			return err
		})
		if err != nil {
			return current, fmt.Errorf("migrations: applying %s: %w", s.name, err)
		}
		current = s.version
	}
	return current, nil
}

type step struct {
	version int
	name    string
	sql     string
}

func upSteps() ([]step, error) {
	names, err := fs.Glob(FS, "*.up.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	out := make([]step, 0, len(names))
	for _, n := range names {
		v, err := strconv.Atoi(strings.SplitN(n, "_", 2)[0])
		if err != nil {
			return nil, fmt.Errorf("migrations: %s has no numeric version", n)
		}
		b, err := FS.ReadFile(n)
		if err != nil {
			return nil, err
		}
		out = append(out, step{version: v, name: n, sql: string(b)})
	}
	return out, nil
}
