// Package migrations holds the EVM accessor's PostgreSQL migrations: every table the accessor owns,
// whichever feature needs it. The LogPoller schema is the first.
package migrations

import "embed"

//go:embed postgres/*.sql
var PostgresMigrations embed.FS
