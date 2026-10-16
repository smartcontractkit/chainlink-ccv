package evm

import (
	"fmt"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// logPollerGuard is package-level because the verifier rebuilds its accessor registry on every job
// start, so only process-wide state can see that a previous registry still holds a chain. Tests
// share it and run in parallel by each using a chain ID no other test holds.
var logPollerGuard = newChainGuard()

// chainGuard lets one holder at a time run a LogPoller per evm_chain_id: two writers on the same
// chain's rows would corrupt each other's block and log state.
type chainGuard struct {
	mu   sync.Mutex
	held map[string]protocol.ChainSelector
}

func newChainGuard() *chainGuard {
	return &chainGuard{held: make(map[string]protocol.ChainSelector)}
}

// acquire claims chainID for selector.
func (g *chainGuard) acquire(chainID string, selector protocol.ChainSelector) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if holder, ok := g.held[chainID]; ok {
		return fmt.Errorf(
			"log poller for evm_chain_id %s is already held by chain selector %d, refusing chain selector %d",
			chainID, holder, selector)
	}
	g.held[chainID] = selector
	return nil
}

// release frees chainID only if selector holds it, so a repeated or stale release cannot free a
// chain that another holder has since taken.
func (g *chainGuard) release(chainID string, selector protocol.ChainSelector) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.held[chainID] == selector {
		delete(g.held, chainID)
	}
}
