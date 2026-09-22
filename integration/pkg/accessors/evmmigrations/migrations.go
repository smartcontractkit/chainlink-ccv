// Package evmmigrations owns the `evm` LogPoller schema for the standalone verifier,
// which builds its own LogPoller and so has nothing else to create those tables. In-node
// the node's migrator owns the schema and this package must not run.
//
// The DDL is generated -- see tools/logpollerschema.
package evmmigrations

import "embed"

//go:embed postgres/*.sql
var PostgresMigrations embed.FS
