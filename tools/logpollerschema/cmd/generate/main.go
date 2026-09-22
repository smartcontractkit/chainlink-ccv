// Command generate writes the initial `evm` LogPoller migration from a pg_dump produced
// by tools/logpollerschema/derive.sh. Run from the module root:
//
//	go run ./tools/logpollerschema/cmd/generate
package main

import (
	"github.com/smartcontractkit/chainlink-ccv/tools/logpollerschema"
)

func main() { logpollerschema.Main() }
