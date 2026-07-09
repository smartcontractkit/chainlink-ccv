// Command generate renders configuration documentation for this repo's apps from
// their Go config/secrets structs. Run from the module root:
//
//	go run ./tools/configdoc/cmd/generate -o docs/config
//
// It writes one *.documented.toml file per registered target (see the
// tools/configdoc/registry package). With -check it verifies the committed docs
// are up to date instead of writing, exiting non-zero on drift — the same
// guarantee the companion freshness test enforces in CI.
//
// The command body is a single call to configdoc.Main; another repo's command is
// the same one-liner with its own registry.
package main

import (
	"github.com/smartcontractkit/chainlink-ccv/tools/configdoc"
	"github.com/smartcontractkit/chainlink-ccv/tools/configdoc/registry"
)

func main() { configdoc.Main(registry.Targets) }
