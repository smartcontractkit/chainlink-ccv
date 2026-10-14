package constructors

import (
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"
)

// newLogPollerConfig wires a chain's log poller source reader to the node's log poller.
func newLogPollerConfig(chain legacyevm.Chain, verifierID string) *evm.LogPollerConfig {
	return &evm.LogPollerConfig{
		LogPoller:  chain.LogPoller(),
		VerifierID: verifierID,
		Retention:  evm.DefaultMessageSentLogRetention,
	}
}
