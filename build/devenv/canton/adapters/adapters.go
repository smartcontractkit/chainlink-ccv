package adapters

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-canton/contracts"
	tokenadapters "github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/sequences"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

var (
	_ tokenadapters.TokenAdapter = &CantonTokenAdapter{}
	_ adapters.ChainFamily       = &CantonAdapter{}
)

// TODO: move this to chainlink-canton/deployment.
type CantonTokenAdapter struct {
	base tokenadapters.TokenAdapter
}

// NewTokenAdapter creates a new Canton token adapter.
// A "base" adapter needs to be passed in, currently assumed to be the EVM token adapter,
// in order to achieve all functionality.
// TODO: this needs to be fully implemented for Canton.
func NewTokenAdapter(base tokenadapters.TokenAdapter) *CantonTokenAdapter {
	return &CantonTokenAdapter{
		base: base,
	}
}

// AddressRefToBytes implements tokens.TokenAdapter.
func (t *CantonTokenAdapter) AddressRefToBytes(ref datastore.AddressRef) ([]byte, error) {
	return contracts.RawInstanceAddressFromString(ref.Address).InstanceAddress().Bytes(), nil
}

// ConfigureTokenForTransfersSequence implements tokens.TokenAdapter.
func (t *CantonTokenAdapter) ConfigureTokenForTransfersSequence() *operations.Sequence[tokenadapters.ConfigureTokenForTransfersInput, sequences.OnChainOutput, chain.BlockChains] {
	return t.base.ConfigureTokenForTransfersSequence()
}

// DeployToken implements tokens.TokenAdapter.
func (t *CantonTokenAdapter) DeployToken() *operations.Sequence[tokenadapters.DeployTokenInput, sequences.OnChainOutput, chain.BlockChains] {
	return t.base.DeployToken()
}

// DeployTokenPoolForToken implements tokens.TokenAdapter.
func (t *CantonTokenAdapter) DeployTokenPoolForToken() *operations.Sequence[tokenadapters.DeployTokenPoolInput, sequences.OnChainOutput, chain.BlockChains] {
	return t.base.DeployTokenPoolForToken()
}

// DeployTokenVerify implements tokens.TokenAdapter.
func (t *CantonTokenAdapter) DeployTokenVerify(e deployment.Environment, in any) error {
	return t.base.DeployTokenVerify(e, in)
}

// ManualRegistration implements tokens.TokenAdapter.
func (t *CantonTokenAdapter) ManualRegistration() *operations.Sequence[tokenadapters.ManualRegistrationInput, sequences.OnChainOutput, chain.BlockChains] {
	return t.base.ManualRegistration()
}

// RegisterToken implements tokens.TokenAdapter.
func (t *CantonTokenAdapter) RegisterToken() *operations.Sequence[tokenadapters.RegisterTokenInput, sequences.OnChainOutput, chain.BlockChains] {
	return t.base.RegisterToken()
}

// SetPool implements tokens.TokenAdapter.
func (t *CantonTokenAdapter) SetPool() *operations.Sequence[tokenadapters.SetPoolInput, sequences.OnChainOutput, chain.BlockChains] {
	return t.base.SetPool()
}

// UpdateAuthorities implements tokens.TokenAdapter.
func (t *CantonTokenAdapter) UpdateAuthorities() *operations.Sequence[tokenadapters.UpdateAuthoritiesInput, sequences.OnChainOutput, chain.BlockChains] {
	return t.base.UpdateAuthorities()
}

func (t *CantonTokenAdapter) DeriveTokenAddress(e deployment.Environment, chainSelector uint64, ref datastore.AddressRef) ([]byte, error) {
	addr, err := e.DataStore.Addresses().Get(datastore.NewAddressRefKey(chainSelector, ref.Type, ref.Version, ref.Qualifier))
	if err != nil {
		return nil, fmt.Errorf("failed to get address for %v on chain %d: %w", ref, chainSelector, err)
	}

	return contracts.RawInstanceAddressFromString(addr.Address).InstanceAddress().Bytes(), nil
}

// CantonAdapter is an implementation of the ChainFamily interface for Canton.
type CantonAdapter struct {
	base adapters.ChainFamily
}

// NewChainFamilyAdapter creates a new Canton chain family adapter.
// A "base" adapter needs to be passed in, currently assumed to be the EVM chain family adapter,
// in order to achieve all functionality.
// TODO: this needs to be fully implemented for Canton.
func NewChainFamilyAdapter(base adapters.ChainFamily) *CantonAdapter {
	return &CantonAdapter{
		base: base,
	}
}

// AddressRefToBytes implements adapters.ChainFamily.
func (c *CantonAdapter) AddressRefToBytes(ref datastore.AddressRef) ([]byte, error) {
	// Canton uses two different types of addresses:
	// - "Raw" instance addresses, which are of the format "prefix@party-id" and are stored as strings in the datastore.
	// - InstanceAddresses, which are the 32-byte keccak256 hash of the raw instance address, and are used for all remote-chain configurations.
	// Parsing the raw version from the datastore and converting it to the hashed version to keep all remote-chain address references of the same length.
	return contracts.RawInstanceAddressFromString(ref.Address).InstanceAddress().Bytes(), nil
}

// ConfigureChainForLanes implements adapters.ChainFamily.
func (c *CantonAdapter) ConfigureChainForLanes() *operations.Sequence[adapters.ConfigureChainForLanesInput, sequences.OnChainOutput, chain.BlockChains] {
	return c.base.ConfigureChainForLanes()
}
