package migrations

import "embed"

//go:embed postgres/*.sql
var PostgresMigrations embed.FS
