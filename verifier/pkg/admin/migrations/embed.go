package migrations

import "embed"

// PostgresMigrations holds the admin console's own schema migrations. They run with a
// dedicated goose version table so the console DB never collides with verifier
// migrations, even if an operator points both at one database.
//
//go:embed postgres/*.sql
var PostgresMigrations embed.FS
