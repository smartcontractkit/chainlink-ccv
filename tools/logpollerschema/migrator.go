//go:build ignore

// Derives the authoritative end-state `evm` schema by running the Chainlink node's
// real migrator against a scratch database, then dumping the result.
//
// This is the authoring tool for the generated evm schema AND its drift check.
// Authoring tool, not a CI step. Drift is caught by running the pinned ORM's own test
// suite against the schema (just logpoller-orm-contract); re-derive only when you want to
// see what changed upstream, e.g. before writing a delta migration.
//
// Why the real migrator rather than `goose up` over the SQL files: the node's set
// includes four Go migrations, and Migration56 creates `evm_chains`, which 0115's
// foreign key depends on. It also calls goose.ResetGlobalMigrations() as a documented
// workaround. Running the node's own provider sidesteps all of that.
//
// Place this inside the chainlink repo (e.g. tools/logpollerschema/main.go) so it builds
// against that module, and run it from a checkout at the ref you want to pin.
//
//	go run ./tools/logpollerschema -dsn "postgres://postgres:postgres@localhost:5432/logpollerschema?sslmode=disable"
//
// NOTE: the pgx driver is required, not lib/pq. Migration 0229 contains an explicit
// BEGIN/COMMIT inside a body goose already wraps in a transaction; lib/pq tracks
// transaction state strictly and fails with "unexpected transaction status idle",
// while pgx tolerates it. The node pins pgx for the same reason -- see
// core/services/pg/connection.go.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/smartcontractkit/chainlink/v2/core/store/migrate"
)

func main() {
	dsn := flag.String("dsn", "", "scratch postgres DSN (database must exist and be empty)")
	flag.Parse()

	if *dsn == "" {
		fmt.Fprintln(os.Stderr, "-dsn is required")
		os.Exit(2)
	}

	ctx := context.Background()

	db, err := sql.Open("pgx", *dsn)
	if err != nil {
		fatal("open: %v", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		fatal("ping: %v", err)
	}

	provider, err := migrate.NewProvider(ctx, db)
	if err != nil {
		fatal("new provider: %v", err)
	}

	results, err := provider.Up(ctx)
	if err != nil {
		fatal("migrate up: %v", err)
	}

	fmt.Fprintf(os.Stderr, "applied %d migrations\n", len(results))
	if len(results) > 0 {
		fmt.Fprintf(os.Stderr, "highest version: %d\n", results[len(results)-1].Source.Version)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
