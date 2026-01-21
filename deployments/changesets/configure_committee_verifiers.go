package changesets

import (
	"fmt"
	"slices"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	changesets_core "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	changesets_1_7_0 "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/changesets"
	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

// CommitteeVerifierRemoteChainConfig configures the CommitteeVerifier for a remote chain.
type CommitteeVerifierRemoteChainConfig struct {
	// Whether to allow traffic TO the remote chain.
	AllowlistEnabled bool
	// Addresses that are allowed to send messages TO the remote chain.
	AddedAllowlistedSenders []string
	// Addresses that are no longer allowed to send messages TO the remote chain.
	RemovedAllowlistedSenders []string
	// The fee in USD cents charged for verification on the remote chain.
	FeeUSDCents uint16
	// The gas required to execute the verification call on the destination chain (used for billing).
	GasForVerification uint32
	// The size of the CCV specific payload in bytes (used for billing).
	PayloadSizeBytes uint32
}

// CommitteeVerifierConfig configures a CommitteeVerifier contract.
type CommitteeVerifierConfig struct {
	CommitteeQualifier string
	// RemoteChains specifies the configuration for each remote chain supported by the committee verifier.
	RemoteChains map[uint64]CommitteeVerifierRemoteChainConfig
}

type PartialChainConfig struct {
	// The selector of the chain being configured.
	ChainSelector uint64
	// The Router on the chain being configured.
	// We assume that all connections defined will use the same router, either test or production.
	Router datastore.AddressRef
	// The OnRamp on the chain being configured.
	// Similarly, we assume that all connections will use the same OnRamp.
	OnRamp datastore.AddressRef
	// The CommitteeVerifiers on the chain being configured.
	// There can be multiple committee verifiers on a chain, each controlled by a different entity.
	CommitteeVerifiers []CommitteeVerifierConfig
	// The FeeQuoter on the chain being configured.
	FeeQuoter datastore.AddressRef
	// The OffRamp on the chain being configured
	OffRamp datastore.AddressRef
	// The configuration for each remote chain that we want to connect to.
	RemoteChains map[uint64]adapters.RemoteChainConfig[datastore.AddressRef, datastore.AddressRef]
}

// ConfigureChainsForLanesConfig is the configuration for the ConfigureChainsForLanes changeset.
type ConfigureChainsForLanesFromTopologyConfig struct {
	Topology *deployments.EnvironmentTopology
	// Chains specifies the chains to configure.
	Chains []PartialChainConfig
	// MCMS configures the resulting proposal.
	MCMS mcms.Input
}

// ConfigureCommitteeVerifiersFromTopology creates a changeset that configures
// CommitteeVerifier contracts with signers and thresholds from the topology.
func ConfigureChainsForLanesFromTopology(chainFamilyRegistry *adapters.ChainFamilyRegistry, mcmsRegistry *changesets_core.MCMSReaderRegistry) deployment.ChangeSetV2[ConfigureChainsForLanesFromTopologyConfig] {
	validate := func(e deployment.Environment, cfg ConfigureChainsForLanesFromTopologyConfig) error {
		if cfg.Topology == nil {
			return fmt.Errorf("topology is required")
		}

		if len(cfg.Topology.NOPTopology.Committees) == 0 {
			return fmt.Errorf("no committees defined in topology")
		}

		for _, chain := range cfg.Chains {
			if !slices.Contains(e.BlockChains.ListChainSelectors(), chain.ChainSelector) {
				return fmt.Errorf("chain selector %d is not available in environment", chain.ChainSelector)
			}
		}

		return nil
	}

	apply := func(e deployment.Environment, cfg ConfigureChainsForLanesFromTopologyConfig) (deployment.ChangesetOutput, error) {
		if cfg.Topology == nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("topology is required")
		}

		chains := make([]changesets_1_7_0.ChainConfig, 0, len(cfg.Chains))
		for _, chain := range cfg.Chains {
			committeeVerifiers := make([]adapters.CommitteeVerifierConfig[datastore.AddressRef], 0, len(chain.CommitteeVerifiers))
			for _, committeeVerifier := range chain.CommitteeVerifiers {
				remoteChains := make(map[uint64]adapters.CommitteeVerifierRemoteChainConfig, len(committeeVerifier.RemoteChains))
				for remoteChainSelector, remoteChainConfig := range committeeVerifier.RemoteChains {
					signatureConfig, err := getSignatureConfigForSourceChain(cfg.Topology, committeeVerifier.CommitteeQualifier, remoteChainSelector)
					if err != nil {
						return deployment.ChangesetOutput{}, fmt.Errorf("failed to get signature config for source chain %d: %w", remoteChainSelector, err)
					}
					remoteChains[remoteChainSelector] = adapters.CommitteeVerifierRemoteChainConfig{
						AllowlistEnabled:          remoteChainConfig.AllowlistEnabled,
						AddedAllowlistedSenders:   remoteChainConfig.AddedAllowlistedSenders,
						RemovedAllowlistedSenders: remoteChainConfig.RemovedAllowlistedSenders,
						FeeUSDCents:               remoteChainConfig.FeeUSDCents,
						GasForVerification:        remoteChainConfig.GasForVerification,
						PayloadSizeBytes:          remoteChainConfig.PayloadSizeBytes,
						SignatureConfig:           *signatureConfig,
					}
				}

				committeeVerifierAddresses := e.DataStore.Addresses().Filter(
					datastore.AddressRefByChainSelector(chain.ChainSelector),
					datastore.AddressRefByType(datastore.ContractType(committee_verifier.ContractType)),
					datastore.AddressRefByQualifier(committeeVerifier.CommitteeQualifier),
				)
				if len(committeeVerifierAddresses) == 0 {
					return deployment.ChangesetOutput{}, fmt.Errorf("no committee verifier addresses found for chain %d and committee qualifier %q", chain.ChainSelector, committeeVerifier.CommitteeQualifier)
				}

				committeeVerifierResolverAddresses := e.DataStore.Addresses().Filter(
					datastore.AddressRefByChainSelector(chain.ChainSelector),
					datastore.AddressRefByType(datastore.ContractType(committee_verifier.ResolverType)),
					datastore.AddressRefByQualifier(committeeVerifier.CommitteeQualifier),
				)
				if len(committeeVerifierResolverAddresses) == 0 {
					return deployment.ChangesetOutput{}, fmt.Errorf("no committee verifier resolver addresses found for chain %d and committee qualifier %q", chain.ChainSelector, committeeVerifier.CommitteeQualifier)
				}

				committeeVerifiers = append(committeeVerifiers, adapters.CommitteeVerifierConfig[datastore.AddressRef]{
					CommitteeVerifier: []datastore.AddressRef{
						{
							Address:       committeeVerifierAddresses[0].Address,
							ChainSelector: chain.ChainSelector,
							Qualifier:     committeeVerifier.CommitteeQualifier,
						},
						{
							Address:       committeeVerifierResolverAddresses[0].Address,
							ChainSelector: chain.ChainSelector,
							Qualifier:     committeeVerifier.CommitteeQualifier,
						},
					},
					RemoteChains: remoteChains,
				})
			}
			chains = append(chains, changesets_1_7_0.ChainConfig{
				ChainSelector:      chain.ChainSelector,
				RemoteChains:       chain.RemoteChains,
				FeeQuoter:          chain.FeeQuoter,
				OnRamp:             chain.OnRamp,
				OffRamp:            chain.OffRamp,
				Router:             chain.Router,
				CommitteeVerifiers: committeeVerifiers,
			})
		}

		return changesets_1_7_0.ConfigureChainsForLanes(chainFamilyRegistry, mcmsRegistry).Apply(e, changesets_1_7_0.ConfigureChainsForLanesConfig{
			Chains: chains,
			MCMS:   cfg.MCMS,
		})
	}

	return deployment.CreateChangeSet(apply, validate)
}

func getSignatureConfigForSourceChain(
	topology *deployments.EnvironmentTopology,
	committeeQualifier string,
	chainSelector uint64,
) (*adapters.CommitteeVerifierSignatureQuorumConfig, error) {
	committee, ok := topology.NOPTopology.Committees[committeeQualifier]
	if !ok {
		return nil, fmt.Errorf("committee %q not found", committeeQualifier)
	}

	chainCfg, ok := committee.ChainConfigs[fmt.Sprintf("%d", chainSelector)]
	if !ok {
		return nil, fmt.Errorf("chain selector %d not found in committee %q", chainSelector, committeeQualifier)
	}

	signers := make([]string, 0, len(chainCfg.NOPAliases))
	for _, alias := range chainCfg.NOPAliases {
		nop, ok := topology.NOPTopology.GetNOP(alias)
		if !ok {
			return nil, fmt.Errorf("NOP alias %q not found for committee %q chain %d", alias, committeeQualifier, chainSelector)
		}
		family, err := chainsel.GetSelectorFamily(chainSelector)
		if err != nil {
			return nil, fmt.Errorf("failed to get selector family for selector %d: %w", chainSelector, err)
		}
		signerAddress, ok := nop.SignerAddressByFamily[family]
		if !ok {
			return nil, fmt.Errorf("NOP %q missing signer_address for family %s on committee %q chain %d", alias, family, committeeQualifier, chainSelector)
		}
		signers = append(signers, signerAddress)
	}

	signatureConfig := &adapters.CommitteeVerifierSignatureQuorumConfig{
		Threshold: chainCfg.Threshold,
		Signers:   signers,
	}
	return signatureConfig, nil
}
