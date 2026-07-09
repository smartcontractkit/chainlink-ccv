package configdoc

import (
	"flag"
	"fmt"
	"os"
)

// Main is the shared entrypoint for a configdoc command. A consuming repo's
// command is then a single line:
//
//	func main() { configdoc.Main(registry.Targets) }
//
// It parses the standard flags (-o output dir, -check verify mode), builds a
// Generator by auto-detecting the enclosing module from the working directory,
// and either writes the docs or verifies they are up to date — exiting non-zero
// on any error or on drift in -check mode. Run it from within the module whose
// structs are being documented (the comment extractor needs that source tree).
func Main(targets []Target) {
	out := flag.String("o", "docs/config", "output directory for generated docs")
	check := flag.Bool("check", false, "verify committed docs are up to date instead of writing")
	flag.Parse()

	cwd, err := os.Getwd()
	if err != nil {
		fatal(err)
	}
	g, err := NewGenerator(cwd)
	if err != nil {
		fatal(err)
	}

	if *check {
		stale, err := g.Check(targets, *out)
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

	written, err := g.Write(targets, *out)
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
