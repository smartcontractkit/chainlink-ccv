package canton

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	adminv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2/admin"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	chainsel "github.com/smartcontractkit/chain-selectors"
	evmadapters "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	dsutils "github.com/smartcontractkit/chainlink-ccip/deployment/utils/datastore"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/canton"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
	"github.com/smartcontractkit/go-daml/pkg/types"

	"github.com/smartcontractkit/chainlink-canton/bindings/generated/ccip/ccvs"
	"github.com/smartcontractkit/chainlink-canton/bindings/generated/ccip/common"
	"github.com/smartcontractkit/chainlink-canton/bindings/generated/ccip/rmn"
	"github.com/smartcontractkit/chainlink-canton/contracts"
	cantonChangesets "github.com/smartcontractkit/chainlink-canton/deployment/changesets"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/committee_verifier"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/fee_quoter"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/global_config"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/offramp"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/onramp"
	"github.com/smartcontractkit/chainlink-canton/deployment/sequences"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	cantonadapters "github.com/smartcontractkit/chainlink-ccv/devenv/canton/adapters"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

var (
	_ cciptestinterfaces.CCIP17              = &Chain{}
	_ cciptestinterfaces.CCIP17Configuration = &Chain{}
)

type Chain struct {
	e            *deployment.Environment
	chain        canton.Chain
	logger       zerolog.Logger
	chainDetails chainsel.ChainDetails
}

func New(ctx context.Context, logger zerolog.Logger, e *deployment.Environment, chainID string) (*Chain, error) {
	chainDetails, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyCanton)
	if err != nil {
		return nil, fmt.Errorf("get chain details for chain %s: %w", chainID, err)
	}
	chain := e.BlockChains.CantonChains()[chainDetails.ChainSelector]

	return &Chain{
		e:            e,
		chain:        chain,
		chainDetails: chainDetails,
		logger:       logger,
	}, nil
}

func NewEmptyCCIP17Canton(logger zerolog.Logger) *Chain {
	return &Chain{
		logger: logger,
	}
}

// ChainFamily implements cciptestinterfaces.CCIP17Configuration.
func (c *Chain) ChainFamily() string {
	return chainsel.FamilyCanton
}

// ConfigureNodes implements cciptestinterfaces.CCIP17Configuration.
func (c *Chain) ConfigureNodes(ctx context.Context, blockchain *blockchain.Input) (string, error) {
	return "", nil // TODO: implement
}

// DeployContractsForSelector implements cciptestinterfaces.CCIP17Configuration.
func (c *Chain) DeployContractsForSelector(ctx context.Context, env *deployment.Environment, selector uint64, topology *deployments.EnvironmentTopology) (datastore.DataStore, error) {
	// Only using a single participant for now
	participant := env.BlockChains.CantonChains()[selector].Participants[0]

	// Deploy the json-tests DAR so that it's available on the network.
	// NOTE: this is hacky, but temporary, until we deploy the real CCIP contracts.
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	darPath := filepath.Join(dir, "../tests/integration/canton/json-tests-0.0.1.dar")
	dar, err := os.ReadFile(darPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read json-tests DAR: %w", err)
	}
	_, err = participant.LedgerServices.Admin.PackageManagement.UploadDarFile(ctx, &adminv2.UploadDarFileRequest{
		DarFile: dar,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload json-tests DAR: %w", err)
	}

	l := c.logger
	l.Info().Msg("Configuring contracts for selector")
	l.Info().Any("Selector", selector).Msg("Deploying for chain selectors")
	runningDS := datastore.NewMemoryDataStore()

	l.Info().Uint64("Selector", selector).Msg("Configuring per-chain contracts bundle")
	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		env.Logger,
		operations.NewMemoryReporter(),
	)
	env.OperationsBundle = bundle

	l.Info().Msg("Uploading and vetting CCIP DARs...")
	commonDar, err := contracts.GetDar(contracts.CCIPCommon, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get common dar file")
	}
	_, err = participant.LedgerServices.Admin.PackageManagement.UploadDarFile(ctx, &adminv2.UploadDarFileRequest{
		DarFile: commonDar,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload common dar file")
	}
	offRampDar, err := contracts.GetDar(contracts.CCIPOffRamp, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get offramp dar file")
	}
	_, err = participant.LedgerServices.Admin.PackageManagement.UploadDarFile(ctx, &adminv2.UploadDarFileRequest{
		DarFile: offRampDar,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload offramp dar file")
	}
	onRampDar, err := contracts.GetDar(contracts.CCIPOnRamp, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get onramp dar file")
	}
	_, err = participant.LedgerServices.Admin.PackageManagement.UploadDarFile(ctx, &adminv2.UploadDarFileRequest{
		DarFile: onRampDar,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload onramp dar file")
	}
	tokenAdminRegistryDar, err := contracts.GetDar(contracts.CCIPTokenAdminRegistry, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get token admin registry dar file")
	}
	_, err = participant.LedgerServices.Admin.PackageManagement.UploadDarFile(ctx, &adminv2.UploadDarFileRequest{
		DarFile: tokenAdminRegistryDar,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload token admin registry dar file")
	}
	committeeVerifierDar, err := contracts.GetDar(contracts.CCIPCommitteeVerifier, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get committee verifier dar file")
	}
	_, err = participant.LedgerServices.Admin.PackageManagement.UploadDarFile(ctx, &adminv2.UploadDarFileRequest{
		DarFile: committeeVerifierDar,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload committee verifier dar file")
	}
	tokenPoolDar, err := contracts.GetDar(contracts.CCIPLockReleaseTokenPool, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get token pool dar file")
	}
	_, err = participant.LedgerServices.Admin.PackageManagement.UploadDarFile(ctx, &adminv2.UploadDarFileRequest{
		DarFile: tokenPoolDar,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload token pool dar file")
	}
	perPartyRouterDar, err := contracts.GetDar(contracts.CCIPPerPartyRouter, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get per-party router dar file")
	}
	_, err = participant.LedgerServices.Admin.PackageManagement.UploadDarFile(ctx, &adminv2.UploadDarFileRequest{
		DarFile: perPartyRouterDar,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload per-party router dar file")
	}

	l.Info().Any("selector", selector).Any("party", participant.PartyID).Msg("Deploying chain contracts")
	config := cantonChangesets.CantonCSDeps[cantonChangesets.DeployChainContractsConfig]{
		ChainSelector: selector,
		Participant:   0,
		Config: cantonChangesets.DeployChainContractsConfig{
			Params: sequences.DeployChainContractsParams{
				CCIPOwnerParty:     participant.PartyID,
				CommitteeVerifiers: nil,
				GlobalConfig: sequences.GlobalConfigParams{
					Template: common.GlobalConfig{
						CcipOwner:     "", // Populated by the sequence
						ChainSelector: types.NUMERIC(strconv.FormatUint(selector, 10)),
						OnRampAddress: "", // TODO ?
					},
				},
				RMNRemote: sequences.RMNRemoteParams{
					Template: rmn.RMNRemote{
						RmnOwner:       types.PARTY(participant.PartyID),
						CursedSubjects: nil,
					},
				},
			},
		},
	}

	// Get committees
	for qualifier, committeeConfig := range topology.NOPTopology.Committees {
		var storageLocation types.TEXT // TODO, multiple storage locations
		if len(committeeConfig.StorageLocations) > 0 {
			storageLocation = types.TEXT(committeeConfig.StorageLocations[0])
		} else {
			storageLocation = types.TEXT("dummy-location") // TODO contracts don't allow an empty location for now
		}
		cv := sequences.CommitteeVerifierParams{
			Qualifier: qualifier,
			Template: ccvs.CommitteeVerifier{
				Owner:               types.PARTY(participant.PartyID), // TODO: use different ccv owner?
				CcipOwner:           types.PARTY(participant.PartyID),
				VersionTag:          types.TEXT("49ff34ed"),
				MessageSentObserver: types.PARTY(participant.PartyID),
				StorageLocation:     storageLocation,
			},
		}
		config.Config.Params.CommitteeVerifiers = append(config.Config.Params.CommitteeVerifiers, cv)
	}

	out, err := cantonChangesets.DeployChainContracts{}.Apply(*env, config)
	if err != nil {
		return nil, fmt.Errorf("failed to deploy chain contracts for selector %d: %w", selector, err)
	}
	err = runningDS.Merge(out.DataStore.Seal())
	if err != nil {
		return nil, err
	}

	// Mock out a Canton deployment for now.
	// Add token pools
	for i, combo := range devenvcommon.AllTokenCombinations() {
		addressRef := combo.DestPoolAddressRef()
		err = runningDS.AddressRefStore.Add(datastore.AddressRef{
			Address:       contracts.MustNewInstanceID("dst-token-pool-" + strconv.Itoa(i)).RawInstanceAddress(types.PARTY(participant.PartyID)).InstanceAddress().Hex(),
			Type:          addressRef.Type,
			Version:       addressRef.Version,
			Qualifier:     addressRef.Qualifier,
			ChainSelector: selector,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to add dst token pool address ref: %w", err)
		}
	}
	// Add executor refs
	err = runningDS.AddressRefStore.Add(datastore.AddressRef{
		Address:       contracts.MustNewInstanceID("executor-1").RawInstanceAddress(types.PARTY(participant.PartyID)).InstanceAddress().Hex(),
		Type:          datastore.ContractType(executor.ContractType),
		Version:       executor.Version,
		Qualifier:     devenvcommon.DefaultExecutorQualifier,
		ChainSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add executor address ref: %w", err)
	}
	err = runningDS.AddressRefStore.Add(datastore.AddressRef{
		Address:       contracts.MustNewInstanceID("executor-proxy-1").RawInstanceAddress(types.PARTY(participant.PartyID)).InstanceAddress().String(),
		Type:          datastore.ContractType(executor.ProxyType),
		Version:       executor.Version,
		Qualifier:     devenvcommon.DefaultExecutorQualifier,
		ChainSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add executor proxy address ref: %w", err)
	}

	return runningDS.Seal(), nil
}

// ConnectContractsWithSelectors implements cciptestinterfaces.CCIP17Configuration.
func (c *Chain) ConnectContractsWithSelectors(ctx context.Context, env *deployment.Environment, selector uint64, remoteSelectors []uint64, committees *deployments.EnvironmentTopology) error {
	l := c.logger
	l.Info().Uint64("FromSelector", selector).Any("ToSelectors", remoteSelectors).Msg("Connecting contracts with selectors")
	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		env.Logger,
		operations.NewMemoryReporter(),
	)
	env.OperationsBundle = bundle

	formatFunc := func(ref datastore.AddressRef) (contracts.InstanceAddress, error) {
		return contracts.HexToInstanceAddress(ref.Address), nil
	}

	// Get InstanceAddresses of Canton contracts
	globalConfig, err := dsutils.FindAndFormatRef(env.DataStore, datastore.AddressRef{
		Type: datastore.ContractType(global_config.ContractType),
	}, selector, formatFunc)
	if err != nil {
		return fmt.Errorf("failed to get global config address for chain %d: %w", selector, err)
	}
	feeQuoter, err := dsutils.FindAndFormatRef(env.DataStore, datastore.AddressRef{
		Type: datastore.ContractType(fee_quoter.ContractType),
	}, selector, formatFunc)
	if err != nil {
		return fmt.Errorf("failed to get fee quoter address for chain %d: %w", selector, err)
	}
	onRamp, err := dsutils.FindAndFormatRef(env.DataStore, datastore.AddressRef{
		Type: datastore.ContractType(onramp.ContractType),
	}, selector, formatFunc)
	if err != nil {
		return fmt.Errorf("failed to get on ramp address for chain %d: %w", selector, err)
	}
	offRamp, err := dsutils.FindAndFormatRef(env.DataStore, datastore.AddressRef{
		Type: datastore.ContractType(offramp.ContractType),
	}, selector, formatFunc)
	if err != nil {
		return fmt.Errorf("failed to get off ramp address for chain %d: %w", selector, err)
	}

	config := cantonChangesets.CantonCSDeps[cantonChangesets.ConfigureChainForLanesConfig]{
		ChainSelector: selector,
		Participant:   0,
		Config: cantonChangesets.ConfigureChainForLanesConfig{
			Input: sequences.ConfigureChainForLanesInput{
				ChainSelector:      0,
				GlobalConfig:       globalConfig,
				FeeQuoter:          feeQuoter,
				OnRamp:             onRamp,
				OffRamp:            offRamp,
				CommitteeVerifiers: []adapters.CommitteeVerifierConfig[contracts.InstanceAddress]{},
				RemoteChains:       make(map[uint64]adapters.RemoteChainConfig[[]byte, contracts.RawInstanceAddress], len(remoteSelectors)),
			},
		},
	}

	for _, remoteSelector := range remoteSelectors {
		// TODO: should be moved to the ChainFamily interface.
		var addressBytesLength uint8
		family, err := chainsel.GetSelectorFamily(remoteSelector)
		if err != nil {
			return fmt.Errorf("failed to get selector family for chain %d: %w", remoteSelector, err)
		}
		var chainFamily adapters.ChainFamily
		switch family {
		case chainsel.FamilyEVM:
			addressBytesLength = 20
			chainFamily = &evmadapters.ChainFamilyAdapter{}
		case chainsel.FamilyCanton:
			addressBytesLength = 32
			chainFamily = cantonadapters.NewChainFamilyAdapter(&evmadapters.ChainFamilyAdapter{})
		default:
			return fmt.Errorf("unsupported family %s for chain %d", family, remoteSelector)
		}

		remoteOnRamp, err := dsutils.FindAndFormatRef(env.DataStore, datastore.AddressRef{
			Type:    datastore.ContractType(onramp.ContractType),
			Version: onramp.Version,
		}, remoteSelector, chainFamily.AddressRefToBytes)
		if err != nil {
			return fmt.Errorf("failed to get on ramp address for remote chain %d: %w", remoteSelector, err)
		}
		remoteOffRamp, err := dsutils.FindAndFormatRef(env.DataStore, datastore.AddressRef{
			Type:    datastore.ContractType(offramp.ContractType),
			Version: offramp.Version,
		}, remoteSelector, chainFamily.AddressRefToBytes)
		if err != nil {
			return fmt.Errorf("failed to get off ramp address for remote chain %d: %w", remoteSelector, err)
		}

		remoteChainConfig := adapters.RemoteChainConfig[[]byte, contracts.RawInstanceAddress]{
			AllowTrafficFrom:         true,
			OnRamps:                  [][]byte{remoteOnRamp},
			OffRamp:                  remoteOffRamp,
			DefaultInboundCCVs:       nil,
			LaneMandatedInboundCCVs:  nil,
			DefaultOutboundCCVs:      nil,
			LaneMandatedOutboundCCVs: nil,
			DefaultExecutor:          "",
			FeeQuoterDestChainConfig: adapters.FeeQuoterDestChainConfig{},
			ExecutorDestChainConfig:  adapters.ExecutorDestChainConfig{},
			AddressBytesLength:       addressBytesLength,
			BaseExecutionGasCost:     0,
		}
		config.Config.Input.RemoteChains[remoteSelector] = remoteChainConfig
	}

	for qualifier, committee := range committees.NOPTopology.Committees {
		// Get CommitteeVerifier address for this qualifier
		committeeVerifier, err := dsutils.FindAndFormatRef(env.DataStore, datastore.AddressRef{
			Type:      datastore.ContractType(committee_verifier.ContractType),
			Qualifier: qualifier,
		}, selector, formatFunc)
		if err != nil {
			return fmt.Errorf("failed to get committee verifier address with qualifier %s for chain %d: %w", qualifier, selector, err)
		}

		committeeVerifierConfig := adapters.CommitteeVerifierConfig[contracts.InstanceAddress]{
			CommitteeVerifier: []contracts.InstanceAddress{committeeVerifier},
			RemoteChains:      make(map[uint64]adapters.CommitteeVerifierRemoteChainConfig),
		}

		// Configure all remote chains with the respective signers
		for _, remoteSelector := range remoteSelectors {
			chainCfg, ok := committee.ChainConfigs[strconv.FormatUint(remoteSelector, 10)]
			if !ok {
				return fmt.Errorf("chain selector %d not found in committee %q", remoteSelector, qualifier)
			}
			// For each of the NOPs in this committee, get their Canton-family signer.
			// Since the Canton CommitteeVerifier requires the (uncompressed) signer pubkey to be set on-chain,
			// nop.SignerAddressByFamily[chainsel.FamilyCanton] must contain the signer's pubkey, NOT address
			signers := make([]string, 0, len(chainCfg.NOPAliases))
			for _, alias := range chainCfg.NOPAliases {
				nop, ok := committees.NOPTopology.GetNOP(alias)
				if !ok {
					return fmt.Errorf("NOP alias %q not found for committee %q chain %d", alias, qualifier, remoteSelector)
				}
				signer, ok := nop.SignerAddressByFamily[chainsel.FamilyCanton]
				if !ok {
					return fmt.Errorf("no Canton pubkey signer found for NOP alias %q", alias)
				}
				signers = append(signers, signer)
			}
			committeeVerifierConfig.RemoteChains[remoteSelector] = adapters.CommitteeVerifierRemoteChainConfig{
				AllowlistEnabled:          false,
				AddedAllowlistedSenders:   nil,
				RemovedAllowlistedSenders: nil,
				FeeUSDCents:               0,
				GasForVerification:        0,
				PayloadSizeBytes:          0,
				SignatureConfig: adapters.CommitteeVerifierSignatureQuorumConfig{
					Signers:   signers,
					Threshold: chainCfg.Threshold,
				},
			}
		}
		config.Config.Input.CommitteeVerifiers = append(config.Config.Input.CommitteeVerifiers, committeeVerifierConfig)
	}

	_, err = cantonChangesets.ConfigureChainForLanes{}.Apply(*env, config)
	if err != nil {
		return fmt.Errorf("failed to configure chain for lanes: %w", err)
	}

	return nil
}

// DeployLocalNetwork implements cciptestinterfaces.CCIP17Configuration.
func (c *Chain) DeployLocalNetwork(ctx context.Context, bcs *blockchain.Input) (*blockchain.Output, error) {
	c.logger.
		Info().
		Int("NumberOfCantonValidators", bcs.NumberOfCantonValidators).
		Msg("Deploying Canton network")
	out, err := blockchain.NewBlockchainNetwork(bcs)
	if err != nil {
		return nil, fmt.Errorf("failed to create blockchain network: %w", err)
	}

	return out, nil
}

// FundAddresses implements cciptestinterfaces.CCIP17Configuration.
func (c *Chain) FundAddresses(ctx context.Context, bc *blockchain.Input, addresses []protocol.UnknownAddress, nativeAmount *big.Int) error {
	return nil // TODO: implement
}

// FundNodes implements cciptestinterfaces.CCIP17Configuration.
func (c *Chain) FundNodes(ctx context.Context, cls []*simple_node_set.Input, bc *blockchain.Input, linkAmount, nativeAmount *big.Int) error {
	return nil // TODO: implement
}

// Curse implements cciptestinterfaces.CCIP17.
func (c *Chain) Curse(ctx context.Context, subjects [][16]byte) error {
	return nil // TODO: implement
}

// ExposeMetrics implements cciptestinterfaces.CCIP17.
func (c *Chain) ExposeMetrics(ctx context.Context, source, dest uint64) ([]string, *prometheus.Registry, error) {
	return nil, nil, nil // TODO: implement
}

// GetEOAReceiverAddress implements cciptestinterfaces.CCIP17.
func (c *Chain) GetEOAReceiverAddress() (protocol.UnknownAddress, error) {
	return protocol.UnknownAddress{}, nil // TODO: implement
}

// GetExpectedNextSequenceNumber implements cciptestinterfaces.CCIP17.
func (c *Chain) GetExpectedNextSequenceNumber(ctx context.Context, to uint64) (uint64, error) {
	return 0, nil // TODO: implement
}

// GetMaxDataBytes implements cciptestinterfaces.CCIP17.
func (c *Chain) GetMaxDataBytes(ctx context.Context, remoteChainSelector uint64) (uint32, error) {
	return 0, nil // TODO: implement
}

// GetRoundRobinUser implements cciptestinterfaces.CCIP17.
func (c *Chain) GetRoundRobinUser() func() *bind.TransactOpts {
	return nil // TODO: implement
}

// GetSenderAddress implements cciptestinterfaces.CCIP17.
func (c *Chain) GetSenderAddress() (protocol.UnknownAddress, error) {
	return protocol.UnknownAddress{}, nil // TODO: implement
}

// GetTokenBalance implements cciptestinterfaces.CCIP17.
func (c *Chain) GetTokenBalance(ctx context.Context, address, tokenAddress protocol.UnknownAddress) (*big.Int, error) {
	return nil, nil // TODO: implement
}

// GetUserNonce implements cciptestinterfaces.CCIP17.
func (c *Chain) GetUserNonce(ctx context.Context, userAddress protocol.UnknownAddress) (uint64, error) {
	return 0, nil // TODO: implement
}

// SendMessage implements cciptestinterfaces.CCIP17.
func (c *Chain) SendMessage(ctx context.Context, dest uint64, fields cciptestinterfaces.MessageFields, opts cciptestinterfaces.MessageOptions) (cciptestinterfaces.MessageSentEvent, error) {
	return cciptestinterfaces.MessageSentEvent{}, nil // TODO: implement
}

// SendMessageWithNonce implements cciptestinterfaces.CCIP17.
func (c *Chain) SendMessageWithNonce(ctx context.Context, dest uint64, fields cciptestinterfaces.MessageFields, opts cciptestinterfaces.MessageOptions, sender *bind.TransactOpts, nonce *atomic.Uint64, disableTokenAmountCheck bool) (cciptestinterfaces.MessageSentEvent, error) {
	return cciptestinterfaces.MessageSentEvent{}, nil // TODO: implement
}

// Uncurse implements cciptestinterfaces.CCIP17.
func (c *Chain) Uncurse(ctx context.Context, subjects [][16]byte) error {
	return nil // TODO: implement
}

// WaitOneExecEventBySeqNo implements cciptestinterfaces.CCIP17.
func (c *Chain) WaitOneExecEventBySeqNo(ctx context.Context, from, seq uint64, timeout time.Duration) (cciptestinterfaces.ExecutionStateChangedEvent, error) {
	return cciptestinterfaces.ExecutionStateChangedEvent{}, nil // TODO: implement
}

// WaitOneSentEventBySeqNo implements cciptestinterfaces.CCIP17.
func (c *Chain) WaitOneSentEventBySeqNo(ctx context.Context, to, seq uint64, timeout time.Duration) (cciptestinterfaces.MessageSentEvent, error) {
	return cciptestinterfaces.MessageSentEvent{}, nil // TODO: implement
}
