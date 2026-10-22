package db

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/scylladb/go-reflectx"
)

// NewLogPollerDB wraps the shared pool for the chainlink-evm LogPoller ORM, which needs snake_case
// column mapping. It reuses db rather than opening a second pool, so callers must never Close the result.
func NewLogPollerDB(db *sql.DB) *sqlx.DB {
	handle := sqlx.NewDb(db, "postgres")
	handle.MapperFunc(reflectx.CamelToSnakeASCII)
	return handle
}
