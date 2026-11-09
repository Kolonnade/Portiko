// Package migrations holds Portiko's schema as ordered SQL files, in the
// golang-migrate naming scheme (NNNNNN_name.up.sql / .down.sql).
//
// Apply runs them against a database, and provider.Migrate and the `portiko
// migrate` command call it. The golang-migrate CLI reads the same files and
// the same schema_migrations table, so an operator who prefers it can use it.
package migrations

import (
	"embed"
	"io/fs"
	"sort"
	"strings"
)

//go:embed *.sql
var FS embed.FS

// Up returns the contents of every up migration, in order.
func Up() ([]string, error) {
	names, err := fs.Glob(FS, "*.up.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, n := range names {
		b, err := FS.ReadFile(n)
		if err != nil {
			return nil, err
		}
		out = append(out, strings.TrimSpace(string(b)))
	}
	return out, nil
}
