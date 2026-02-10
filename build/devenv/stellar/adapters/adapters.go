package adapters

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/sequences"
	adapters "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

var _ adapters.ChainFamily = &StellarAdapter{}

// StellarAdapter is an implementation of the ChainFamily interface for Stellar.
type StellarAdapter struct {
	base adapters.ChainFamily
}

// NewChainFamilyAdapter creates a new Stellar chain family adapter.
// A "base" adapter needs to be passed in, currently assumed to be the EVM chain family adapter,
// in order to achieve all functionality.
// TODO: this needs to be fully implemented for Stellar.
func NewChainFamilyAdapter(base adapters.ChainFamily) *StellarAdapter {
	return &StellarAdapter{
		base: base,
	}
}

// AddressRefToBytes implements adapters.ChainFamily.
// Stellar contract addresses are stored as hex-encoded strings in the DataStore.
func (s *StellarAdapter) AddressRefToBytes(ref datastore.AddressRef) ([]byte, error) {
	decoded, err := hexutil.Decode(ref.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Stellar address %q: %w", ref.Address, err)
	}
	return decoded, nil
}

// ConfigureChainForLanes implements adapters.ChainFamily.
// TODO: implement Stellar-specific chain lane configuration.
func (s *StellarAdapter) ConfigureChainForLanes() *operations.Sequence[adapters.ConfigureChainForLanesInput, sequences.OnChainOutput, chain.BlockChains] {
	return s.base.ConfigureChainForLanes()
}
