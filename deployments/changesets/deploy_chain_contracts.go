package changesets

import (
	"fmt"
	"slices"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"

	evmchangesets "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/changesets"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/sequences"
	changesetscore "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

// DeployChainContractsFromTopologyCfg is the configuration for deploying chain contracts
// with CommitteeVerifier params derived from the topology.
type DeployChainContractsFromTopologyCfg struct {
	Topology       *deployments.EnvironmentTopology
	ChainSelector  uint64
	CREATE2Factory common.Address

	// Non-topology params (passed through to DeployChainContracts)
	RMNRemote     sequences.RMNRemoteParams
	OffRamp       sequences.OffRampParams
	OnRamp        sequences.OnRampParams
	FeeQuoter     sequences.FeeQuoterParams
	Executors     []sequences.ExecutorParams
	MockReceivers []sequences.MockReceiverParams
}

// DeployChainContractsFromTopology creates a changeset that deploys all chain contracts
// with CommitteeVerifier configuration derived from the topology.
// This wraps the chainlink-ccip DeployChainContracts changeset, reading committee
// qualifiers, versions, and on-chain params (fee_aggregator, allowlist_admin, storage_locations)
// from the topology file.
func DeployChainContractsFromTopology(
	mcmsReaderRegistry *changesetscore.MCMSReaderRegistry,
) deployment.ChangeSetV2[changesetscore.WithMCMS[DeployChainContractsFromTopologyCfg]] {
	validate := func(e deployment.Environment, cfg changesetscore.WithMCMS[DeployChainContractsFromTopologyCfg]) error {
		if cfg.Cfg.Topology == nil {
			return fmt.Errorf("topology is required")
		}

		if len(cfg.Cfg.Topology.NOPTopology.Committees) == 0 {
			return fmt.Errorf("no committees defined in topology")
		}

		envSelectors := e.BlockChains.ListChainSelectors()
		if !slices.Contains(envSelectors, cfg.Cfg.ChainSelector) {
			return fmt.Errorf("chain selector %d is not available in environment", cfg.Cfg.ChainSelector)
		}

		if cfg.Cfg.CREATE2Factory == (common.Address{}) {
			return fmt.Errorf("CREATE2Factory address is required")
		}

		return nil
	}

	apply := func(e deployment.Environment, cfg changesetscore.WithMCMS[DeployChainContractsFromTopologyCfg]) (deployment.ChangesetOutput, error) {
		if cfg.Cfg.Topology == nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("topology is required")
		}

		committeeVerifiers, err := BuildCommitteeVerifierParams(cfg.Cfg.Topology)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to build committee verifier params: %w", err)
		}

		innerCfg := changesetscore.WithMCMS[evmchangesets.DeployChainContractsCfg]{
			MCMS: cfg.MCMS,
			Cfg: evmchangesets.DeployChainContractsCfg{
				ChainSel:       cfg.Cfg.ChainSelector,
				CREATE2Factory: cfg.Cfg.CREATE2Factory,
				Params: sequences.ContractParams{
					RMNRemote:          cfg.Cfg.RMNRemote,
					OffRamp:            cfg.Cfg.OffRamp,
					CommitteeVerifiers: committeeVerifiers,
					OnRamp:             cfg.Cfg.OnRamp,
					FeeQuoter:          cfg.Cfg.FeeQuoter,
					Executors:          cfg.Cfg.Executors,
					MockReceivers:      cfg.Cfg.MockReceivers,
				},
			},
		}

		e.Logger.Info(
			"Deploying chain contracts with topology-derived committee verifiers",
			"chain", cfg.Cfg.ChainSelector,
			"committees", len(committeeVerifiers),
		)

		return evmchangesets.DeployChainContracts(mcmsReaderRegistry).Apply(e, innerCfg)
	}

	return deployment.CreateChangeSet(apply, validate)
}

// BuildCommitteeVerifierParams builds CommitteeVerifierParams from the topology.
// If qualifiers is empty, all committees from the topology are included.
// This function is exported so devenv can use it with in-memory topology.
func BuildCommitteeVerifierParams(
	topology *deployments.EnvironmentTopology,
) ([]sequences.CommitteeVerifierParams, error) {
	params := make([]sequences.CommitteeVerifierParams, 0, len(topology.NOPTopology.Committees))
	for qualifier := range topology.NOPTopology.Committees {
		committee, ok := topology.NOPTopology.Committees[qualifier]
		if !ok {
			return nil, fmt.Errorf("committee %q not found in topology", qualifier)
		}

		params = append(params, sequences.CommitteeVerifierParams{
			Version:          semver.MustParse("1.7.0"),
			FeeAggregator:    common.HexToAddress(committee.FeeAggregator),
			AllowlistAdmin:   common.HexToAddress(committee.AllowlistAdmin),
			StorageLocations: committee.StorageLocations,
			Qualifier:        qualifier,
		})
	}

	return params, nil
}
