package adapters

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"

	mcmstypes "github.com/smartcontractkit/mcms/types"

	cldfchain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/operations/contract"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldfops "github.com/smartcontractkit/chainlink-deployments-framework/operations"

	evm1adapters "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/adapters"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/token_admin_registry"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/token_pool"

	ccvadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// EVMCCVTokenPoolOnchainAdapter implements ccvadapters.TokenPoolOnchainAdapter for
// EVM chains. It is registered into the ccv adapter registry from init() so that
// ccv/deployment changesets can reconfigure token pools chain-family-agnostically.
type EVMCCVTokenPoolOnchainAdapter struct{}

var _ ccvadapters.TokenPoolOnchainAdapter = (*EVMCCVTokenPoolOnchainAdapter)(nil)

// evmTokenBase is a stateless helper used to resolve local contract addresses
// (e.g. the TokenAdminRegistry) from the datastore.
var evmTokenBase = &evm1adapters.EVMTokenBase{}

// evmRemoveRemotePool resolves the token's active pool from the TokenAdminRegistry,
// verifies the requested remote pool is currently configured for the remote chain
// (erroring clearly if it is not), and issues removeRemotePool. The removeRemotePool
// operation is executed directly when the deployer key owns the pool, or simulated
// and returned as an MCMS batch operation when the pool is owned by a timelock.
var evmRemoveRemotePool = cldfops.NewSequence(
	"evm-remove-remote-pool",
	semver.MustParse("2.0.0"),
	"Removes a single remote pool from a token's pool on an EVM chain",
	func(b cldfops.Bundle, chains cldfchain.BlockChains, input ccvadapters.RemoveRemotePoolInput) (ccvadapters.RemoveRemotePoolOutput, error) {
		evmChain, ok := chains.EVMChains()[input.ChainSelector]
		if !ok {
			return ccvadapters.RemoveRemotePoolOutput{}, fmt.Errorf("EVM chain %d not found in environment", input.ChainSelector)
		}

		registry, err := resolveTokenAdminRegistryEVM(laneLocalDataStore(input.ExistingAddresses), input.ChainSelector, input.RegistryAddress)
		if err != nil {
			return ccvadapters.RemoveRemotePoolOutput{}, err
		}

		pool, err := resolveActivePoolEVM(b, evmChain, input.ChainSelector, input.TokenAddress, registry)
		if err != nil {
			return ccvadapters.RemoveRemotePoolOutput{}, err
		}

		// Verify the requested remote pool is currently configured for the remote chain.
		poolsReport, err := cldfops.ExecuteOperation(
			b, token_pool.GetRemotePools, evmChain,
			contract.FunctionInput[uint64]{ChainSelector: input.ChainSelector, Address: pool, Args: input.RemoteChainSelector},
			cldfops.WithForceExecute[contract.FunctionInput[uint64], evm.Chain](),
		)
		if err != nil {
			return ccvadapters.RemoveRemotePoolOutput{}, fmt.Errorf("failed to get remote pools for token %s remote chain %d on chain %d: %w", input.TokenAddress, input.RemoteChainSelector, input.ChainSelector, err)
		}
		// Remote pool addresses are stored left-padded to 32 bytes on chain; match the input the same way.
		target := common.LeftPadBytes(input.RemotePoolAddress, 32)
		if !slices.ContainsFunc(poolsReport.Output, func(p []byte) bool { return bytes.Equal(p, target) }) {
			return ccvadapters.RemoveRemotePoolOutput{}, fmt.Errorf(
				"remote pool 0x%x is not configured for token %s remote chain %d on pool %s (chain %d)",
				input.RemotePoolAddress, input.TokenAddress, input.RemoteChainSelector, pool.Hex(), input.ChainSelector,
			)
		}

		writeReport, err := cldfops.ExecuteOperation(
			b, token_pool.RemoveRemotePool, evmChain,
			contract.FunctionInput[token_pool.RemoveRemotePoolArgs]{
				ChainSelector: input.ChainSelector,
				Address:       pool,
				Args: token_pool.RemoveRemotePoolArgs{
					RemoteChainSelector: input.RemoteChainSelector,
					RemotePoolAddress:   target,
				},
			},
		)
		if err != nil {
			return ccvadapters.RemoveRemotePoolOutput{}, fmt.Errorf("failed to remove remote pool for token %s remote chain %d on chain %d: %w", input.TokenAddress, input.RemoteChainSelector, input.ChainSelector, err)
		}

		// Wrap the write into an MCMS batch operation. NewBatchOperationFromWrites
		// drops writes already executed with the deployer key, yielding an empty
		// batch op in deployer-key mode (filtered out downstream by the changeset).
		batchOp, err := contract.NewBatchOperationFromWrites([]contract.WriteOutput{writeReport.Output})
		if err != nil {
			return ccvadapters.RemoveRemotePoolOutput{}, fmt.Errorf("failed to build batch operation for chain %d: %w", input.ChainSelector, err)
		}

		return ccvadapters.RemoveRemotePoolOutput{BatchOps: []mcmstypes.BatchOperation{batchOp}}, nil
	},
)

func (a *EVMCCVTokenPoolOnchainAdapter) RemoveRemotePool() *cldfops.Sequence[ccvadapters.RemoveRemotePoolInput, ccvadapters.RemoveRemotePoolOutput, cldfchain.BlockChains] {
	return evmRemoveRemotePool
}

// ResolveRemotePoolAddress resolves the token's active pool on chainSelector and
// returns its address bytes — the form a counterpart chain stores to reference this
// EVM pool. On EVM the stored remote-pool address is the deployed pool address
// itself (DeriveTokenPoolCounterpart is the identity), so no derivation is needed;
// the local chain left-pads it to 32 bytes when matching on-chain state.
func (a *EVMCCVTokenPoolOnchainAdapter) ResolveRemotePoolAddress(e deployment.Environment, chainSelector uint64, tokenAddress string) ([]byte, error) {
	evmChain, ok := e.BlockChains.EVMChains()[chainSelector]
	if !ok {
		return nil, fmt.Errorf("EVM chain %d not found in environment", chainSelector)
	}
	registry, err := resolveTokenAdminRegistryEVM(e.DataStore, chainSelector, "")
	if err != nil {
		return nil, err
	}
	pool, err := resolveActivePoolEVM(e.OperationsBundle, evmChain, chainSelector, tokenAddress, registry)
	if err != nil {
		return nil, err
	}
	return pool.Bytes(), nil
}

// resolveTokenAdminRegistryEVM resolves the TokenAdminRegistry address from the
// explicit override when set, otherwise from the datastore.
func resolveTokenAdminRegistryEVM(ds datastore.DataStore, chainSelector uint64, override string) (common.Address, error) {
	if override != "" {
		if !common.IsHexAddress(override) {
			return common.Address{}, fmt.Errorf("invalid registry address %q on chain %d", override, chainSelector)
		}
		return common.HexToAddress(override), nil
	}
	registry, err := evmTokenBase.GetTokenAdminRegistryAddress(ds, chainSelector)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to resolve TokenAdminRegistry on chain %d: %w", chainSelector, err)
	}
	return registry, nil
}

// resolveActivePoolEVM reads the token's active pool from the TokenAdminRegistry.
// WithForceExecute because it reflects mutable on-chain state that may have been
// read (and cached) earlier in this bundle.
func resolveActivePoolEVM(b cldfops.Bundle, evmChain evm.Chain, chainSelector uint64, tokenAddress string, registry common.Address) (common.Address, error) {
	if !common.IsHexAddress(tokenAddress) {
		return common.Address{}, fmt.Errorf("invalid token address %q on chain %d", tokenAddress, chainSelector)
	}
	token := common.HexToAddress(tokenAddress)

	cfgReport, err := cldfops.ExecuteOperation(
		b, token_admin_registry.GetTokenConfig, evmChain,
		contract.FunctionInput[common.Address]{ChainSelector: chainSelector, Address: registry, Args: token},
		cldfops.WithForceExecute[contract.FunctionInput[common.Address], evm.Chain](),
	)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to get token config from registry %s for token %s on chain %d: %w", registry.Hex(), token.Hex(), chainSelector, err)
	}
	pool := cfgReport.Output.TokenPool
	if pool == (common.Address{}) {
		return common.Address{}, fmt.Errorf("no active pool registered for token %s on chain %d", token.Hex(), chainSelector)
	}
	return pool, nil
}
