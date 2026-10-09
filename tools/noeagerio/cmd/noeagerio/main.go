// Command noeagerio is a vettool that reports I/O in constructors and Start
// methods. Run it via go vet:
//
//	go vet -vettool=$(which noeagerio) ./...
//
// See the noeagerio package docs for the rule and its rationale.
package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/smartcontractkit/chainlink-ccv/tools/noeagerio"
)

func main() {
	singlechecker.Main(noeagerio.Analyzer)
}
