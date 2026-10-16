package logpollerdb

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/scylladb/go-reflectx"
)

// NewDB wraps the shared pool for the chainlink-evm ORM, which needs snake_case column mapping.
// It reuses db rather than opening a second pool, so callers must never Close the result.
func NewDB(db *sql.DB) *sqlx.DB {
	handle := sqlx.NewDb(db, "postgres")
	handle.MapperFunc(reflectx.CamelToSnakeASCII)
	return handle
}
