// Command eventuallytimeout is a vettool that rejects Testify Eventually timeouts below 10s.
// Run with: go vet -vettool=$(which eventuallytimeout) ./...
package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/smartcontractkit/chainlink-ccv/tools/eventuallytimeout"
)

func main() {
	singlechecker.Main(eventuallytimeout.Analyzer)
}
