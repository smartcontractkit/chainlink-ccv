// Command generate renders configuration documentation for this repo's apps from
// their Go config/secrets structs. Run from the module root:
//
//	go run ./tools/configdoc/cmd/generate -o docs/config
//
// It writes one *.documented.toml file per registered target (see the
// tools/configdoc/registry package). With -check it verifies the committed docs
// are up to date instead of writing, exiting non-zero on drift — the same
// guarantee the companion freshness test enforces in CI.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/smartcontractkit/chainlink-ccv/tools/configdoc"
	"github.com/smartcontractkit/chainlink-ccv/tools/configdoc/registry"
)

func main() {
	out := flag.String("o", "docs/config", "output directory for generated docs")
	check := flag.Bool("check", false, "verify committed docs are up to date instead of writing")
	flag.Parse()

	cwd, err := os.Getwd()
	if err != nil {
		fatal(err)
	}
	g, err := configdoc.NewGenerator(cwd)
	if err != nil {
		fatal(err)
	}

	if *check {
		stale, err := g.Check(registry.Targets, *out)
		if err != nil {
			fatal(err)
		}
		if len(stale) > 0 {
			for _, s := range stale {
				verb := "out of date"
				if s.Missing {
					verb = "missing"
				}
				fmt.Fprintf(os.Stderr, "%s: %s\n", verb, s.Path)
			}
			fmt.Fprintln(os.Stderr, "run: just config-docs")
			os.Exit(1)
		}
		fmt.Println("all config docs up to date")
		return
	}

	written, err := g.Write(registry.Targets, *out)
	if err != nil {
		fatal(err)
	}
	for _, p := range written {
		fmt.Println("wrote", p)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "configdoc:", err)
	os.Exit(1)
}
