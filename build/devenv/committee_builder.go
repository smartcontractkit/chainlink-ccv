package ccv

import (
	"crypto/ecdsa"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/ccv_aggregator"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/ccv_proxy"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_offramp"
	commontypes "github.com/smartcontractkit/chainlink-ccv/common/pkg/types"
	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
)

type committeeQuorumConfig struct {
	SourceVerifierAddress string
	DestVerifierAddress   string
}

type committeeConfig struct {
	SignerCount      int
	Threshold        uint8
	OnChainAddresses map[uint64]*committeeQuorumConfig
}

func (c *committeeConfig) GenerateSigners(name string) ([]ecdsa.PrivateKey, error) {
	signers := make([]ecdsa.PrivateKey, c.SignerCount)
	for i := 0; i < c.SignerCount; i++ {
		seed := fmt.Sprintf("%s-%d", name, i)
		hash := crypto.Keccak256([]byte(seed))
		pk, err := crypto.ToECDSA(hash)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key for signer %d of committee %s: %w", i, name, err)
		}
		signers[i] = *pk
	}
	return signers, nil
}

type CommitteeBuilder struct {
	blockchainInfos map[string]*commontypes.BlockchainInfo
	Committees      map[string]*committeeConfig
}

type CommitteeBuilderWithOnchainAddresses struct {
	CommitteeBuilder
	addresses map[string]struct {
		CCVAddress    string
		CCVAggregator string
	}
}

type CommitteeBuilderOption func(*CommitteeBuilder) *CommitteeBuilder

func WithCommittee(name string, signerCount int, threshold uint8, selectors []uint64) CommitteeBuilderOption {
	return func(cb *CommitteeBuilder) *CommitteeBuilder {
		if cb.Committees == nil {
			cb.Committees = make(map[string]*committeeConfig)
		}

		onchainAddresses := map[uint64]*committeeQuorumConfig{}
		for _, selector := range selectors {
			onchainAddresses[selector] = &committeeQuorumConfig{}
		}

		cb.Committees[name] = &committeeConfig{
			SignerCount:      signerCount,
			Threshold:        threshold,
			OnChainAddresses: onchainAddresses,
		}
		return cb
	}
}

func (cb *CommitteeBuilder) ConfigureOnchain(in *Cfg) *CommitteeBuilderWithOnchainAddresses {
	for name, committee := range cb.Committees {
		config := commit_offramp.SignatureConfigArgs{
			Threshold: committee.Threshold,
			Signers:   make([]common.Address, committee.SignerCount),
		}

		// Generate signers for this committee to populate the config
		signers, err := committee.GenerateSigners(name)
		if err != nil {
			Plog.Error().Err(err).Str("committee", name).Msg("Failed to generate signers for committee")
			continue
		}

		// Populate the signers in the config
		for i := 0; i < committee.SignerCount; i++ {
			address := crypto.PubkeyToAddress(signers[i].PublicKey)
			config.Signers[i] = address
		}

		deploymentResults, err := DeployAndConfigureNewCommitCCV(in, config)
		if err != nil {
			Plog.Error().Err(err).Str("committee", name).Msg("Failed to deploy and configure new commit CCV")
			continue
		}

		// Populate the committee configuration with the deployed contract addresses
		for selector, result := range deploymentResults.Results {
			if quorumConfig, exists := committee.OnChainAddresses[selector]; exists {
				quorumConfig.SourceVerifierAddress = result.OnRampAddress
				quorumConfig.DestVerifierAddress = result.OffRampAddress
			}
		}
	}
	addresses := make(map[string]struct {
		CCVAddress    string
		CCVAggregator string
	})

	for _, chain := range in.Blockchains {
		chainID, err := strconv.ParseUint(chain.ChainID, 10, 64)
		if err != nil {
			Plog.Error().Err(err).Str("chainID", chain.ChainID).Msg("Failed to parse chain ID")
			continue // Skip invalid chain instead of returning nil
		}
		c, exists := chain_selectors.ChainByEvmChainID(chainID)
		if !exists {
			Plog.Warn().Uint64("chainID", chainID).Msg("Chain selector not found, skipping")
			continue // Skip unknown chain instead of returning nil
		}

		ccvProxy := MustGetContractAddressForSelector(in, c.Selector, ccv_proxy.ContractType)
		ccvAggregator := MustGetContractAddressForSelector(in, c.Selector, ccv_aggregator.ContractType)

		addresses[chain.ChainID] = struct {
			CCVAddress    string
			CCVAggregator string
		}{
			CCVAddress:    ccvProxy.Hex(),
			CCVAggregator: ccvAggregator.Hex(),
		}
	}

	return &CommitteeBuilderWithOnchainAddresses{
		CommitteeBuilder: *cb,
		addresses:        addresses,
	}
}

func (cb *CommitteeBuilder) GetOffRampConfigsForSelector(selector uint64) ([]*commit_offramp.SignatureConfigArgs, error) {
	configs := make([]*commit_offramp.SignatureConfigArgs, 0)
	for name, committee := range cb.Committees {
		for s, _ := range committee.OnChainAddresses {
			if s == selector {
				config := &commit_offramp.SignatureConfigArgs{
					Threshold: committee.Threshold,
					Signers:   make([]common.Address, committee.SignerCount),
				}
				signers, err := committee.GenerateSigners(name)
				if err != nil {
					return nil, err
				}
				for i := 0; i < committee.SignerCount; i++ {
					address := crypto.PubkeyToAddress(signers[i].PublicKey)
					config.Signers[i] = address
				}
				configs = append(configs, config)
			}
		}
	}
	return configs, nil
}

func (cb *CommitteeBuilderWithOnchainAddresses) AggregatorCommittee() (map[string]*services.Committee, error) {
	serviceCommittees := make(map[string]*services.Committee)

	for name, config := range cb.Committees {
		// Initialize committee once per name
		serviceCommittees[name] = &services.Committee{
			QuorumConfigs:           make(map[string]*services.QuorumConfig),
			SourceVerifierAddresses: make(map[string]string),
		}

		for selector, addresses := range config.OnChainAddresses {
			serviceCommittees[name].SourceVerifierAddresses[fmt.Sprintf("%d", selector)] = addresses.SourceVerifierAddress
		}

		signers, err := config.GenerateSigners(name)
		if err != nil {
			return nil, err
		}

		// Add all selectors to the same committee
		for selector, addresses := range config.OnChainAddresses {
			quorum := &services.QuorumConfig{
				Threshold:      config.Threshold,
				Signers:        make([]services.Signer, config.SignerCount),
				OfframpAddress: addresses.DestVerifierAddress,
			}

			for i := 0; i < config.SignerCount; i++ {
				address := crypto.PubkeyToAddress(signers[i].PublicKey)
				signer := services.Signer{
					ParticipantID: fmt.Sprintf("%s-%d", name, i),
					Addresses:     []string{address.Hex()},
				}
				quorum.Signers[i] = signer
			}

			selectorStr := fmt.Sprintf("%d", selector)
			serviceCommittees[name].QuorumConfigs[selectorStr] = quorum
		}
	}
	return serviceCommittees, nil
}

func (cb *CommitteeBuilderWithOnchainAddresses) VerifierConfigs() ([]commontypes.VerifierConfig, error) {
	c1337, _ := chain_selectors.ChainByEvmChainID(1337)
	c2337, _ := chain_selectors.ChainByEvmChainID(2337)
	configs := make([]commontypes.VerifierConfig, 0)
	for name, config := range cb.Committees {
		signers, err := config.GenerateSigners(name)
		if err != nil {
			return nil, err
		}
		for _, signer := range signers {
			verifierConfig := commontypes.VerifierConfig{
				AggregatorAddress:  "aggregator:50051", // Default aggregator address
				PrivateKey:         fmt.Sprintf("0x%x", crypto.FromECDSA(&signer)),
				BlockchainInfos:    cb.blockchainInfos,
				VerifierOnRamp1337: config.OnChainAddresses[c1337.Selector].SourceVerifierAddress,
				VerifierOnRamp2337: config.OnChainAddresses[c2337.Selector].SourceVerifierAddress,
				CCVProxy1337:       cb.addresses["1337"].CCVAddress,
				CCVProxy2337:       cb.addresses["2337"].CCVAddress,
			}

			configs = append(configs, verifierConfig)
		}
	}
	return configs, nil
}

func DefaultCommittee() CommitteeBuilderOption {
	return func(cb *CommitteeBuilder) *CommitteeBuilder {
		WithCommittee("default", 2, 2, []uint64{12922642891491394802, 3379446385462418246})(cb)
		WithCommittee("test", 2, 2, []uint64{12922642891491394802, 3379446385462418246})(cb)
		return cb
	}
}

func NewCommitteeBuilder(blockchainInfos map[string]*commontypes.BlockchainInfo, options ...CommitteeBuilderOption) *CommitteeBuilder {
	cb := &CommitteeBuilder{
		Committees:      make(map[string]*committeeConfig),
		blockchainInfos: blockchainInfos,
	}
	for _, opt := range options {
		opt(cb)
	}
	return cb
}
