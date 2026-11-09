package cctp

import (
	"fmt"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// BaseDomainTable returns a chain family's built-in Circle CCTP domain for a chain selector.
// It must be a static lookup: config validation calls it offline, without an accessor.
type BaseDomainTable func(selector protocol.ChainSelector) (uint32, bool)

var (
	baseDomainTables      = make(map[chainaccess.ChainFamily]BaseDomainTable)
	baseDomainTablesMutex sync.RWMutex
)

// RegisterBaseDomainTable registers a family's built-in domain table, from a package that only the
// token verifier binary imports. It panics on a duplicate. A family without one is not checked offline.
func RegisterBaseDomainTable(family chainaccess.ChainFamily, table BaseDomainTable) {
	baseDomainTablesMutex.Lock()
	defer baseDomainTablesMutex.Unlock()

	if _, ok := baseDomainTables[family]; ok {
		panic(fmt.Sprintf("CCTP base domain table for family %s already exists", family))
	}
	baseDomainTables[family] = table
}

// BaseDomainTableFor returns the table registered for a family, if any.
func BaseDomainTableFor(family chainaccess.ChainFamily) (BaseDomainTable, bool) {
	baseDomainTablesMutex.RLock()
	defer baseDomainTablesMutex.RUnlock()

	table, ok := baseDomainTables[family]
	return table, ok
}
