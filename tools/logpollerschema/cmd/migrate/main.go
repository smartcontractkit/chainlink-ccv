// Command migrate applies CCV's generated `evm` LogPoller schema to a given database.
//
// Used by orm-contract.sh so the test database is built through RunEVMMigrations -- the
// same path the verifier uses at startup -- rather than by piping the .sql through psql.
//
//	go run ./tools/logpollerschema/cmd/migrate -dsn "postgres://...?sslmode=disable"
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	_ "github.com/lib/pq"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmmigrations"
)

func main() {
	dsn := flag.String("dsn", "", "postgres DSN of the database to migrate")
	flag.Parse()

	if *dsn == "" {
		fmt.Fprintln(os.Stderr, "-dsn is required")
		os.Exit(2)
	}

	ctx := context.Background()

	db, err := sql.Open("postgres", *dsn)
	if err != nil {
		fatal("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.PingContext(ctx); err != nil {
		fatal("ping: %v", err)
	}

	if err := evmmigrations.RunEVMMigrations(ctx, db); err != nil {
		fatal("migrate: %v", err)
	}

	// Named because orm-contract.sh migrates two databases in a row.
	fmt.Fprintf(os.Stderr, "applied the generated evm logpoller schema to %s\n", databaseName(*dsn))
}

// databaseName extracts the database from a DSN for logging. Never returns credentials.
func databaseName(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil || u.Path == "" {
		return "the target database"
	}
	return strings.TrimPrefix(u.Path, "/")
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "migrate: "+format+"\n", args...)
	os.Exit(1)
}
