package changesets

// RemoveRemotePool changeset overview
//
// RemoveRemotePool is a single-entry, onchain-only product that removes one
// remote pool entry from a token's pool on a single chain. It is the inverse of
// the AddRemotePool step that runs implicitly inside ConfigureTokensForTransfers
// during upgrade cutover: adding a remote pool has a path, removing one did not.
//
// Operators identify the remote pool by the *remote token*, not by a raw remote
// pool address. The changeset asks the remote chain's adapter to resolve its own
// pool address (ResolveRemotePoolAddress), so chain families whose pool address is
// derived rather than deployed (e.g. Solana PDAs) resolve it themselves and
// operators never hand-encode one. An explicit RemotePoolAddress override is
// available for removing a specific/stale entry.
//
// The local chain's adapter then resolves the token's active pool from the
// TokenAdminRegistry, verifies the resolved remote pool is currently configured
// (clear error if not), and issues removeRemotePool. In MCMS mode the onchain
// write is packaged into a timelock proposal; in deployer-key mode it is
// submitted directly.

import (
	"errors"
	"fmt"
	"slices"

	ccipchangesets "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	mcmsutil "github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// RemoveRemotePoolInput is the imperative input for the RemoveRemotePool changeset.
type RemoveRemotePoolInput struct {
	// ChainSelector is the chain the token pool lives on.
	ChainSelector uint64
	// TokenAddress is the token whose pool is being reconfigured, in the chain
	// family's native string form. The adapter resolves the active pool for this
	// token from the TokenAdminRegistry.
	TokenAddress string
	// RemoteChainSelector is the remote chain whose pool entry is being removed.
	RemoteChainSelector uint64
	// RemoteTokenAddress is the token on RemoteChainSelector, in the remote chain
	// family's native string form. The changeset resolves the remote pool to
	// remove from it via the remote chain's adapter. Required unless
	// RemotePoolAddress is set.
	RemoteTokenAddress string
	// RemotePoolAddress optionally overrides remote-pool resolution with the exact
	// bytes to remove, in the remote family's native byte encoding. Use to remove a
	// specific/stale entry, or when the remote pool is not resolvable from a token.
	RemotePoolAddress []byte
	// RegistryAddress optionally overrides the TokenAdminRegistry on ChainSelector
	// used to resolve the local pool. Empty resolves it from the datastore.
	RegistryAddress string
	// MCMS, when set, packages the onchain removeRemotePool write into an MCMS
	// timelock proposal instead of submitting it with the deployer key.
	MCMS *mcmsutil.Input
}

// RemoveRemotePool removes a single remote pool for a token on a chain
// (single-entry, onchain-only). It resolves the remote pool via the remote
// chain's adapter (unless overridden), then dispatches to the local chain's
// TokenPoolOnchainAdapter. A clear error is returned when the resolved remote
// pool is not currently configured.
func RemoveRemotePool() deployment.ChangeSetV2[RemoveRemotePoolInput] {
	validate := func(e deployment.Environment, cfg RemoveRemotePoolInput) error {
		if cfg.ChainSelector == 0 {
			return errors.New("chain selector is required")
		}
		if cfg.TokenAddress == "" {
			return errors.New("token address is required")
		}
		if cfg.RemoteChainSelector == 0 {
			return errors.New("remote chain selector is required")
		}
		if cfg.ChainSelector == cfg.RemoteChainSelector {
			return errors.New("chain selector and remote chain selector must be different")
		}
		if len(cfg.RemotePoolAddress) == 0 && cfg.RemoteTokenAddress == "" {
			return errors.New("either remote token address or remote pool address is required")
		}
		envSelectors := e.BlockChains.ListChainSelectors()
		if !slices.Contains(envSelectors, cfg.ChainSelector) {
			return fmt.Errorf("chain selector %d is not available in environment", cfg.ChainSelector)
		}
		if _, err := adapters.GetTokenPoolOnchainRegistry().Get(cfg.ChainSelector); err != nil {
			return fmt.Errorf("chain %d: %w", cfg.ChainSelector, err)
		}
		// When resolving from the remote token, the remote chain must be present and
		// have a registered adapter so it can resolve its own pool address.
		if len(cfg.RemotePoolAddress) == 0 {
			if !slices.Contains(envSelectors, cfg.RemoteChainSelector) {
				return fmt.Errorf("remote chain selector %d is not available in environment", cfg.RemoteChainSelector)
			}
			if _, err := adapters.GetTokenPoolOnchainRegistry().Get(cfg.RemoteChainSelector); err != nil {
				return fmt.Errorf("remote chain %d: %w", cfg.RemoteChainSelector, err)
			}
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg RemoveRemotePoolInput) (deployment.ChangesetOutput, error) {
		// Resolve the remote pool bytes to remove: an explicit override wins,
		// otherwise ask the remote chain's adapter to resolve its own pool from the
		// remote token (family-correct, PDA-safe).
		remotePoolAddress := cfg.RemotePoolAddress
		if len(remotePoolAddress) == 0 {
			remoteAdapter, err := adapters.GetTokenPoolOnchainRegistry().Get(cfg.RemoteChainSelector)
			if err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("remote chain %d: %w", cfg.RemoteChainSelector, err)
			}
			remotePoolAddress, err = remoteAdapter.ResolveRemotePoolAddress(e, cfg.RemoteChainSelector, cfg.RemoteTokenAddress)
			if err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("resolve remote pool on chain %d for token %s: %w", cfg.RemoteChainSelector, cfg.RemoteTokenAddress, err)
			}
		}

		adapter, err := adapters.GetTokenPoolOnchainRegistry().Get(cfg.ChainSelector)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("chain %d: %w", cfg.ChainSelector, err)
		}

		report, err := operations.ExecuteSequence(
			e.OperationsBundle,
			adapter.RemoveRemotePool(),
			e.BlockChains,
			adapters.RemoveRemotePoolInput{
				ChainSelector:       cfg.ChainSelector,
				TokenAddress:        cfg.TokenAddress,
				RemoteChainSelector: cfg.RemoteChainSelector,
				RemotePoolAddress:   remotePoolAddress,
				RegistryAddress:     cfg.RegistryAddress,
				ExistingAddresses: e.DataStore.Addresses().Filter(
					datastore.AddressRefByChainSelector(cfg.ChainSelector),
				),
			},
		)
		if err != nil {
			return deployment.ChangesetOutput{Reports: report.ExecutionReports},
				fmt.Errorf("chain %d: RemoveRemotePool failed: %w", cfg.ChainSelector, err)
		}

		e.Logger.Infow("Removed remote pool",
			"chain", cfg.ChainSelector,
			"token", cfg.TokenAddress,
			"remoteChain", cfg.RemoteChainSelector,
		)

		// Package the onchain write: into a timelock proposal with MCMS input, or
		// for deployer-key execution otherwise. The OutputBuilder resolves the
		// per-chain timelock address via the registered MCMS readers when batch ops
		// exist; in deployer-key mode the write is already executed and BatchOps is
		// empty, so Build returns the plain output.
		var mcmsCfg mcmsutil.Input
		if cfg.MCMS != nil {
			mcmsCfg = *cfg.MCMS
		}
		return ccipchangesets.NewOutputBuilder(e, ccipchangesets.GetRegistry()).
			WithReports(report.ExecutionReports).
			WithBatchOps(report.Output.BatchOps).
			Build(mcmsCfg)
	}

	return deployment.CreateChangeSet(apply, validate)
}
