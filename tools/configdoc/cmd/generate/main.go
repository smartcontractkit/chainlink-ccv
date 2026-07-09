// Command generate renders configuration documentation for the apps in this
// repo from their Go config/secrets structs. Run from the module root:
//
//	go run ./tools/configdoc/cmd/generate -o docs/config
//
// It writes one markdown file per registered target (see tools/configdoc's
// Targets). The companion freshness test fails if the committed docs drift from
// what this command would produce.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/smartcontractkit/chainlink-ccv/tools/configdoc"
)

const modulePath = "github.com/smartcontractkit/chainlink-ccv"

func main() {
	out := flag.String("o", "docs/config", "output directory for generated docs")
	flag.Parse()

	root, err := os.Getwd()
	if err != nil {
		fatal(err)
	}

	g := &configdoc.Generator{ModuleRoot: root, ModulePath: modulePath}
	for _, t := range configdoc.Targets {
		content, err := g.Render(t)
		if err != nil {
			fatal(err)
		}
		path := filepath.Join(*out, filepath.FromSlash(t.Out))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			fatal(err)
		}
		fmt.Println("wrote", path)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "configdoc:", err)
	os.Exit(1)
}
