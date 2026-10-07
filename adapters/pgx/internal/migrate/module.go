// Package migrate runs the per-module schema migrations of the pgx adapter.
package migrate

import "io/fs"

// Module is one independently migrated schema unit. FS holds its migration files and is nil until
// the module's store lands.
type Module struct {
	Name string
	FS   fs.FS
}
