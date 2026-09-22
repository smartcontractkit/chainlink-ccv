package logpollerschema

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultIn is the pg_dump produced by derive.sh. It is a build artifact, gitignored.
const DefaultIn = "evm-schema/evm-full.sql"

// DefaultRef records which chainlink tree DefaultIn was dumped from. Written by
// derive.sh in the same run, so the two cannot disagree.
const DefaultRef = "evm-schema/chainlink-ref.txt"

// DefaultOut is the generated migration, committed.
const DefaultOut = "integration/pkg/accessors/evmmigrations/postgres/00001_evm_logpoller_schema.sql"

// Main reads a pg_dump of the node's `evm` schema and writes the initial goose migration.
// Run it from the module root.
//
// It authors the *initial* migration only. Once that has been applied anywhere, goose
// records its version and never re-runs it, so regenerating cannot change an existing
// database -- later schema changes belong in new numbered migrations. Use -o to write
// elsewhere when you just want to see the current end state.
//
// Drift between the schema and the pinned ORM is caught by `just logpoller-orm-contract`,
// not by this command.
func Main() {
	in := flag.String("in", DefaultIn, "pg_dump of the node's evm schema (from derive.sh)")
	out := flag.String("o", DefaultOut, "path to write the generated goose migration to")
	refPath := flag.String("ref", DefaultRef, "file recording the chainlink commit the dump came from")
	flag.Parse()

	dump, err := os.ReadFile(*in)
	if err != nil {
		fatal(fmt.Errorf("reading %s: %w (run: just logpoller-schema-derive <path-to-chainlink>)", *in, err))
	}

	ref, err := os.ReadFile(*refPath)
	if err != nil {
		fatal(fmt.Errorf("reading %s: %w (re-run: just logpoller-schema-derive <path-to-chainlink>)", *refPath, err))
	}

	generated, err := Generate(dump, strings.TrimSpace(string(ref)))
	if err != nil {
		fatal(err)
	}

	if err := CheckNotFrozen(*out); err != nil {
		fatal(err)
	}

	if err := os.MkdirAll(filepath.Dir(*out), 0o750); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*out, generated, 0o644); err != nil { //nolint:gosec // G306: generated DDL is committed, not secret
		fatal(err)
	}
	_, _ = fmt.Fprintln(os.Stdout, "wrote", *out)
}

// CheckNotFrozen refuses to overwrite the initial migration once a later one exists.
// A later migration means the initial one has shipped, so overwriting it would change
// what fresh installs get without touching upgraded databases.
func CheckNotFrozen(out string) error {
	dir := filepath.Dir(out)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // first ever run
		}
		return fmt.Errorf("reading %s: %w", dir, err)
	}

	base := filepath.Base(out)
	var later []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") || name == base {
			continue
		}
		if name > base {
			later = append(later, name)
		}
	}
	if len(later) == 0 {
		return nil
	}
	sort.Strings(later)

	return fmt.Errorf(
		"refusing to overwrite %s: it is frozen because later migrations exist (%s).\n"+
			"Once the initial migration has been applied, goose never re-runs it, so regenerating\n"+
			"cannot change a deployed database -- it would only change what fresh installs get.\n"+
			"Add the change as a new numbered migration instead, or pass -o to write elsewhere",
		base, strings.Join(later, ", "))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "logpollerschema:", err)
	os.Exit(1)
}
