package canton

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	apiv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2"
	adminv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2/admin"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

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
	"github.com/smartcontractkit/go-daml/pkg/service/ledger"
	"github.com/smartcontractkit/go-daml/pkg/types"

	"github.com/smartcontractkit/chainlink-canton/bindings/generated/ccip/ccvs"
	"github.com/smartcontractkit/chainlink-canton/bindings/generated/ccip/common"
	"github.com/smartcontractkit/chainlink-canton/bindings/generated/ccip/feequoter"
	"github.com/smartcontractkit/chainlink-canton/bindings/generated/ccip/perpartyrouter"
	"github.com/smartcontractkit/chainlink-canton/bindings/generated/ccip/rmn"
	"github.com/smartcontractkit/chainlink-canton/bindings/generated/ccip/tokenadminregistry"
	splice_api_token_holding_v1 "github.com/smartcontractkit/chainlink-canton/bindings/generated/splice/splice_api_token_holding_v1"
	"github.com/smartcontractkit/chainlink-canton/contracts"
	cantonChangesets "github.com/smartcontractkit/chainlink-canton/deployment/changesets"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/committee_verifier"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/fee_quoter"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/global_config"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/offramp"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/onramp"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/rmn_remote"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/token_admin_registry"
	"github.com/smartcontractkit/chainlink-canton/deployment/sequences"
	"github.com/smartcontractkit/chainlink-canton/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-canton/openapi/gen/scanProxy"
	"github.com/smartcontractkit/chainlink-canton/openapi/gen/tokenMetadataV1"
	"github.com/smartcontractkit/chainlink-canton/openapi/gen/transferInstructionV1"
	"github.com/smartcontractkit/chainlink-ccv/deployments"
	cantonadapters "github.com/smartcontractkit/chainlink-ccv/devenv/canton/adapters"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/devenv/common"
	cantonSourceReader "github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader/canton"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
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
	// Source reader configuration for WaitOneSentEventBySeqNo
	sourceReaderGRPCURL    string
	sourceReaderJWT        string
	sourceReaderTemplateID string
}

func New(ctx context.Context, logger zerolog.Logger, e *deployment.Environment, chainID string) (*Chain, error) {
	return NewWithConfig(ctx, logger, e, chainID, "", "", "")
}

// NewWithConfig creates a new Canton Chain with optional source reader configuration.
// If grpcURL, jwt, or templateID are empty, they will be extracted from the blockchain output if available.
func NewWithConfig(ctx context.Context, logger zerolog.Logger, e *deployment.Environment, chainID, grpcURL, jwt, templateID string) (*Chain, error) {
	chainDetails, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyCanton)
	if err != nil {
		return nil, fmt.Errorf("get chain details for chain %s: %w", chainID, err)
	}
	chain := e.BlockChains.CantonChains()[chainDetails.ChainSelector]

	c := &Chain{
		e:                      e,
		chain:                  chain,
		chainDetails:           chainDetails,
		logger:                 logger,
		sourceReaderGRPCURL:    grpcURL,
		sourceReaderJWT:        jwt,
		sourceReaderTemplateID: templateID,
	}

	return c, nil
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
	feeQuoterDar, err := contracts.GetDar(contracts.CCIPFeeQuoter, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get fee quoter dar file")
	}
	_, err = participant.LedgerServices.Admin.PackageManagement.UploadDarFile(ctx, &adminv2.UploadDarFileRequest{
		DarFile: feeQuoterDar,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload fee quoter dar file")
	}
	ccipSenderDar, err := contracts.GetDar(contracts.CCIPSender, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get CCIPSender dar file")
	}
	_, err = participant.LedgerServices.Admin.PackageManagement.UploadDarFile(ctx, &adminv2.UploadDarFileRequest{
		DarFile: ccipSenderDar,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload CCIPSender dar file")
	}

	l.Info().Any("selector", selector).Any("party", participant.PartyID).Msg("Deploying chain contracts")
	config := cantonChangesets.CantonCSDeps[cantonChangesets.DeployChainContractsConfig]{
		ChainSelector: selector,
		Participant:   0,
		Config: cantonChangesets.DeployChainContractsConfig{
			Params: sequences.DeployChainContractsParams{
				CCIPOwnerParty:     participant.PartyID,
				CommitteeVerifiers: nil,
				FeeQuoterConfig: sequences.FeeQuoterParams{
					Template: feequoter.FeeQuoter{
						PriceUpdaters: []types.PARTY{types.PARTY(participant.PartyID)},
					},
				},
				GlobalConfig: sequences.GlobalConfigParams{
					Template: common.GlobalConfig{
						CcipOwner:     "", // Populated by the sequence
						ChainSelector: types.NUMERIC(strconv.FormatUint(chainsel.CANTON_LOCALNET.Selector, 10)),
						OnRampAddress: "", // TODO ?
					},
				},
				RMNRemote: sequences.RMNRemoteParams{
					Template: rmn.RMNRemote{
						CcipOwner:      "", // Populated by the sequence
						RmnOwner:       types.PARTY(participant.PartyID),
						CursedSubjects: nil,
					},
				},
			},
		},
	}

	// Seed CCV per-dest fee configs so CommitteeVerifier_CalculateFee doesn't fail with:
	//   "no fee config for dest chain"
	//
	// We don't know lane connections yet at deploy time, so we create 0-fee configs for all
	// other chains present in the environment (includes the remote selector we will connect later).
	remoteChainFeeConfigs := types.GENMAP{}
	for _, bc := range env.BlockChains.All() {
		sel := bc.ChainSelector()
		if sel == selector {
			continue
		}
		remoteChainFeeConfigs[strconv.FormatUint(sel, 10)] = ccvs.CCVFeeConfig{
			FeeUSDCents:        types.NUMERIC("0"),
			GasForVerification: types.INT64(0),
			PayloadSizeBytes:   types.INT64(0),
		}.ToMap()
	}

	// Get committees
	for qualifier, committeeConfig := range topology.NOPTopology.Committees {
		chainCfg, ok := committeeConfig.ChainConfigs[strconv.FormatUint(selector, 10)]
		if !ok {
			return nil, fmt.Errorf("chain selector %d not found in committee %q", selector, qualifier)
		}
		var signers []types.TEXT
		for _, nopAlias := range chainCfg.NOPAliases {
			nop, ok := topology.NOPTopology.GetNOP(nopAlias)
			if !ok {
				return nil, fmt.Errorf("NOP alias %q not found for committee %q chain %d", nopAlias, qualifier, selector)
			}

			// Get signing key from config
			// Must use pubkey instead of signer address
			// TODO: implement fetching from JD
			addr, ok := nop.SignerAddressByFamily[chainsel.FamilyCanton]
			if !ok || addr == "" {
				return nil, fmt.Errorf("signer address for NOP alias %q family %q not found for committee %q chain %d", nopAlias, chainsel.FamilyCanton, qualifier, selector)
			}

			signers = append(signers, types.TEXT(strings.TrimPrefix(addr, "0x")))
		}
		var storageLocation types.TEXT // TODO, multiple storage locations
		if len(committeeConfig.StorageLocations) > 0 {
			storageLocation = types.TEXT(committeeConfig.StorageLocations[0])
		} else {
			storageLocation = types.TEXT("ipfs://test-send")
		}
		cv := sequences.CommitteeVerifierParams{
			Qualifier: qualifier,
			Template: ccvs.CommitteeVerifier{
				Owner:                    types.PARTY(participant.PartyID), // TODO: use different ccv owner?
				InstanceId:               "",
				CcipOwner:                types.PARTY(participant.PartyID),
				VersionTag:               types.TEXT("49ff34ed"),
				MessageSentObserver:      types.PARTY(participant.PartyID),
				StorageLocation:          storageLocation,
				Threshold:                types.INT64(chainCfg.Threshold),
				Signers:                  signers,
				RmnRemoteInstanceAddress: common.RawInstanceAddress{}, // Set by sequence
				RemoteChainFeeConfigs:    remoteChainFeeConfigs,
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
				ChainSelector:      selector,
				GlobalConfig:       globalConfig,
				FeeQuoter:          feeQuoter,
				OnRamp:             onRamp,
				OffRamp:            offRamp,
				CommitteeVerifiers: nil,
				RemoteChains:       make(map[uint64]adapters.RemoteChainConfig[[]byte, contracts.RawInstanceAddress], len(remoteSelectors)),
			},
		},
	}

	// Configure outbound defaults: use the default committee verifier as both the outbound CCV and executor,
	// matching the reference integration test.
	var committeeVerifierRawAddr contracts.RawInstanceAddress
	ccvRef, err := env.DataStore.Addresses().Get(datastore.NewAddressRefKey(
		selector,
		datastore.ContractType(committee_verifier.ContractType),
		committee_verifier.Version,
		devenvcommon.DefaultCommitteeVerifierQualifier,
	))
	if err == nil && len(ccvRef.Labels.List()) > 0 {
		committeeVerifierRawAddr = contracts.RawInstanceAddress(ccvRef.Labels.List()[0])
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
		remoteChainConfig := adapters.RemoteChainConfig[[]byte, contracts.RawInstanceAddress]{
			AllowTrafficFrom:         true,
			OnRamps:                  [][]byte{remoteOnRamp},
			OffRamp:                  nil,
			DefaultInboundCCVs:       nil,
			LaneMandatedInboundCCVs:  nil,
			DefaultOutboundCCVs:      []contracts.RawInstanceAddress{committeeVerifierRawAddr},
			LaneMandatedOutboundCCVs: nil,
			DefaultExecutor:          contracts.RawInstanceAddress(string(committeeVerifierRawAddr)),
			FeeQuoterDestChainConfig: adapters.FeeQuoterDestChainConfig{NetworkFeeUSDCents: 0, DefaultTokenFeeUSDCents: 0},
			ExecutorDestChainConfig:  adapters.ExecutorDestChainConfig{},
			AddressBytesLength:       addressBytesLength,
			BaseExecutionGasCost:     0,
		}
		config.Config.Input.RemoteChains[remoteSelector] = remoteChainConfig
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
	if len(c.chain.Participants) == 0 {
		return 0, fmt.Errorf("canton chain not properly initialized: no participants available")
	}

	participant := c.chain.Participants[0]
	senderParty := participant.PartyID

	// Ensure the sender has a router; this is the source of truth for outbound sequence numbers on Canton.
	routerAddress, err := c.DeployPerPartyRouter(ctx, senderParty)
	if err != nil {
		return 0, fmt.Errorf("failed to deploy/get per-party router: %w", err)
	}

	routerActive, err := findLatestActiveContractByInstanceAddress(
		ctx,
		participant.LedgerServices.State,
		participant.PartyID,
		perpartyrouter.PerPartyRouter{}.GetTemplateID(),
		routerAddress,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to get router contract: %w", err)
	}

	created := routerActive.GetCreatedEvent()
	if created == nil || created.GetCreateArguments() == nil {
		return 0, fmt.Errorf("router created event missing create arguments")
	}

	var outboundSeqMap *apiv2.GenMap
	for _, f := range created.GetCreateArguments().GetFields() {
		if f.GetLabel() == "outboundSequenceNumbers" {
			outboundSeqMap = f.GetValue().GetGenMap()
			break
		}
	}
	if outboundSeqMap == nil {
		// Treat missing map as empty: current seq = 0.
		return 1, nil
	}

	dest := to
	var current uint64 = 0
	for _, entry := range outboundSeqMap.GetEntries() {
		keyNum := entry.GetKey().GetNumeric()
		if keyNum == "" {
			continue
		}
		keyU, err := numeric0ToUint64(keyNum)
		if err != nil {
			continue
		}
		if keyU != dest {
			continue
		}
		valNum := entry.GetValue().GetNumeric()
		if valNum == "" {
			current = 0
			break
		}
		valU, err := numeric0ToUint64(valNum)
		if err != nil {
			return 0, fmt.Errorf("failed to parse outboundSequenceNumbers value for dest=%d: %w", dest, err)
		}
		current = valU
		break
	}

	// OnRamp uses newSequenceNumber = currentSequenceNumber + 1.0
	return current + 1, nil
}

func numeric0ToUint64(n string) (uint64, error) {
	// Daml Numeric 0 values are encoded as strings like "5.0"
	if strings.HasSuffix(n, ".0") {
		n = strings.TrimSuffix(n, ".0")
	}
	return strconv.ParseUint(n, 10, 64)
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
// This implementation sends a CCIP message using CCIPSender.Send.
// Reference: integration-tests/testhelpers/ccip_send_e2e_test.go
func (c *Chain) SendMessage(ctx context.Context, dest uint64, fields cciptestinterfaces.MessageFields, opts cciptestinterfaces.MessageOptions) (cciptestinterfaces.MessageSentEvent, error) {
	if len(c.chain.Participants) == 0 {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("canton chain not properly initialized: no participants available")
	}

	participant := c.chain.Participants[0]
	senderParty := participant.PartyID

	// Get sequence number
	seqNo, err := c.GetExpectedNextSequenceNumber(ctx, dest)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get expected next sequence number: %w", err)
	}

	// Get contract addresses from datastore
	onRampRef, err := c.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			c.chainDetails.ChainSelector,
			datastore.ContractType(onramp.ContractType),
			onramp.Version,
			"",
		),
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get onramp address: %w", err)
	}
	onRampAddress := contracts.HexToInstanceAddress(onRampRef.Address)

	// Get executor address and left-pad to 32 bytes to match CCV address length
	if len(opts.Executor) == 0 {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("executor address required")
	}
	executorBytes := opts.Executor
	if len(executorBytes) < 32 {
		// Left-pad with zeros to make it 32 bytes
		padded := make([]byte, 32)
		copy(padded[32-len(executorBytes):], executorBytes)
		executorBytes = padded
	}
	executorAddress := protocol.UnknownAddress(executorBytes)

	// Get CCV addresses from opts.CCVs
	// For Canton, we need to get the actual CCV contract addresses from the datastore
	// since the addresses in opts.CCVs might be in the wrong format (e.g., EVM addresses)
	ccvAddresses := make([]protocol.UnknownAddress, len(opts.CCVs))
	ccvInstanceAddresses := make([]contracts.InstanceAddress, len(opts.CCVs))
	for i, ccv := range opts.CCVs {
		// Try to get CCV address from datastore if we have a qualifier
		// For now, we'll use the default qualifier and get the first CCV
		// TODO: Support multiple CCVs with different qualifiers
		ccvRef, err := c.e.DataStore.Addresses().Get(
			datastore.NewAddressRefKey(
				c.chainDetails.ChainSelector,
				datastore.ContractType(committee_verifier.ContractType),
				committee_verifier.Version,
				devenvcommon.DefaultCommitteeVerifierQualifier,
			),
		)
		if err != nil {
			// Fallback: try to use the address from opts, but convert it properly
			// If it's already a Canton address (32 bytes), convert from bytes
			if len(ccv.CCVAddress) == 32 {
				var addr contracts.InstanceAddress
				copy(addr[:], ccv.CCVAddress)
				ccvInstanceAddresses[i] = addr
			} else {
				// If it's an EVM address (20 bytes) or other format, try to convert from hex string
				// This might fail, but it's better than nothing
				ccvInstanceAddresses[i] = contracts.HexToInstanceAddress(ccv.CCVAddress.String())
			}
		} else {
			// Use the address from datastore (this is the correct Canton InstanceAddress)
			ccvInstanceAddresses[i] = contracts.HexToInstanceAddress(ccvRef.Address)
		}
		// Store the bytes for protocol operations
		ccvAddresses[i] = protocol.UnknownAddress(ccvInstanceAddresses[i].Bytes())
	}

	// Compute CCV and executor hash
	ccvAndExecutorHash, err := protocol.ComputeCCVAndExecutorHash(ccvAddresses, executorAddress)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to compute CCV and executor hash: %w", err)
	}

	// Create the message
	msg, err := protocol.NewMessage(
		protocol.ChainSelector(c.chainDetails.ChainSelector),
		protocol.ChainSelector(dest),
		protocol.SequenceNumber(seqNo),
		protocol.UnknownAddress(onRampAddress.Bytes()),
		executorAddress,
		opts.FinalityConfig,
		opts.ExecutionGasLimit,
		100_000, // ccipReceiveGasLimit - default value
		ccvAndExecutorHash,
		protocol.UnknownAddress{}, // sender - will be set by the router
		fields.Receiver,
		[]byte{}, // destBlob
		fields.Data,
		nil, // tokenTransfer - TODO: support token transfers
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to create message: %w", err)
	}

	// Note: encodedMessage and messageID are extracted from the event after transaction submission
	// We don't need to pre-compute them since they're not used in ccipSendArgs

	// Deploy or get PerPartyRouter for the sender (needed for CCIPSender)
	routerAddress, err := c.DeployPerPartyRouter(ctx, senderParty)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to deploy/get per-party router: %w", err)
	}

	// Get router contract ID
	routerCid, err := findLatestActiveContractIDByInstanceAddress(
		ctx,
		participant.LedgerServices.State,
		participant.PartyID,
		perpartyrouter.PerPartyRouter{}.GetTemplateID(),
		routerAddress,
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get router contract ID: %w", err)
	}

	// Deploy or get CCIPSender for the sender
	ccipSenderCid, ccipSenderEventBlob, ccipSenderTemplateId, err := c.deployOrGetCCIPSender(ctx, senderParty)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to deploy/get CCIPSender: %w", err)
	}

	// Get disclosed contracts needed for CCIPSend
	// We need: OnRamp, GlobalConfig, TokenAdminRegistry, RMNRemote, FeeQuoter, and CCVs
	// Note: We need to use the correct OnRamp binding type
	// For now, we'll use a placeholder - this needs to be fixed based on actual bindings
	onRampActive, err := contract.FindActiveContractByInstanceAddress(
		ctx,
		participant.LedgerServices.State,
		participant.PartyID,
		"#ccip-onramp:CCIP.OnRamp:OnRamp",
		onRampAddress,
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get onramp contract: %w", err)
	}
	disclosedOnRamp := convertToDisclosedContract(onRampActive)

	globalConfigRef, err := c.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			c.chainDetails.ChainSelector,
			datastore.ContractType(global_config.ContractType),
			global_config.Version,
			"",
		),
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get global config address: %w", err)
	}
	globalConfigAddress := contracts.HexToInstanceAddress(globalConfigRef.Address)
	globalConfigActive, err := contract.FindActiveContractByInstanceAddress(
		ctx,
		participant.LedgerServices.State,
		participant.PartyID,
		common.GlobalConfig{}.GetTemplateID(),
		globalConfigAddress,
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get global config contract: %w", err)
	}
	disclosedGlobalConfig := convertToDisclosedContract(globalConfigActive)

	// Get TokenAdminRegistry
	tarRef, err := c.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			c.chainDetails.ChainSelector,
			datastore.ContractType(token_admin_registry.ContractType),
			token_admin_registry.Version,
			"",
		),
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get token admin registry address: %w", err)
	}
	tarAddress := contracts.HexToInstanceAddress(tarRef.Address)
	tarActive, err := contract.FindActiveContractByInstanceAddress(
		ctx,
		participant.LedgerServices.State,
		participant.PartyID,
		tokenadminregistry.TokenAdminRegistry{}.GetTemplateID(),
		tarAddress,
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get token admin registry contract: %w", err)
	}
	disclosedTAR := convertToDisclosedContract(tarActive)

	// Get RMNRemote
	rmnRemoteRef, err := c.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			c.chainDetails.ChainSelector,
			datastore.ContractType(rmn_remote.ContractType),
			rmn_remote.Version,
			"",
		),
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get rmn remote address: %w", err)
	}
	rmnRemoteAddress := contracts.HexToInstanceAddress(rmnRemoteRef.Address)
	rmnRemoteActive, err := contract.FindActiveContractByInstanceAddress(
		ctx,
		participant.LedgerServices.State,
		participant.PartyID,
		rmn.RMNRemote{}.GetTemplateID(),
		rmnRemoteAddress,
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get rmn remote contract: %w", err)
	}
	disclosedRMNRemote := convertToDisclosedContract(rmnRemoteActive)

	// Get FeeQuoter
	feeQuoterRef, err := c.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			c.chainDetails.ChainSelector,
			datastore.ContractType(fee_quoter.ContractType),
			fee_quoter.Version,
			"",
		),
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get fee quoter address: %w", err)
	}
	feeQuoterAddress := contracts.HexToInstanceAddress(feeQuoterRef.Address)
	feeQuoterActive, err := contract.FindActiveContractByInstanceAddress(
		ctx,
		participant.LedgerServices.State,
		participant.PartyID,
		"#ccip-feequoter:CCIP.FeeQuoter:FeeQuoter",
		feeQuoterAddress,
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get fee quoter contract: %w", err)
	}
	disclosedFeeQuoter := convertToDisclosedContract(feeQuoterActive)

	// Get CCV disclosed contracts using the InstanceAddresses we resolved earlier
	disclosedCCVs := make([]*apiv2.DisclosedContract, len(ccvInstanceAddresses))
	for i, ccvInstanceAddr := range ccvInstanceAddresses {
		ccvActive, err := contract.FindActiveContractByInstanceAddress(
			ctx,
			participant.LedgerServices.State,
			participant.PartyID,
			ccvs.CommitteeVerifier{}.GetTemplateID(),
			ccvInstanceAddr,
		)
		if err != nil {
			return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get CCV contract for address %s: %w", ccvInstanceAddr.String(), err)
		}
		disclosedCCVs[i] = convertToDisclosedContract(ccvActive)
	}

	// Prepare disclosed contracts
	disclosedContracts := []*apiv2.DisclosedContract{
		disclosedOnRamp,
		disclosedGlobalConfig,
		disclosedTAR,
		disclosedRMNRemote,
		disclosedFeeQuoter,
	}
	disclosedContracts = append(disclosedContracts, disclosedCCVs...)

	// Get router disclosed contract
	routerActive, err := findLatestActiveContractByInstanceAddress(
		ctx,
		participant.LedgerServices.State,
		participant.PartyID,
		perpartyrouter.PerPartyRouter{}.GetTemplateID(),
		routerAddress,
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get router contract: %w", err)
	}
	disclosedRouter := convertToDisclosedContract(routerActive)
	disclosedContracts = append(disclosedContracts, disclosedRouter)

	// Get CCIPSender disclosed contract
	// Use the actual TemplateId from the created event (this has the real package ID without '#')
	// The '#' prefix is only used in string representations and Create/Exercise commands, not in DisclosedContract
	disclosedCCIPSender := &apiv2.DisclosedContract{
		TemplateId:       ccipSenderTemplateId,
		ContractId:       ccipSenderCid,
		CreatedEventBlob: ccipSenderEventBlob,
		// SynchronizerId will be populated by the ledger if needed
	}
	disclosedContracts = append(disclosedContracts, disclosedCCIPSender)

	// Get fee token information (registry admin, transfer factory, etc.)
	// Create API clients for token metadata and transfer instruction
	tokenSource := participant.TokenSource
	interceptor := func(ctx context.Context, req *http.Request) error {
		token, err := tokenSource.Token()
		if err != nil {
			return fmt.Errorf("failed to retrieve token: %w", err)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
		return nil
	}
	scanProxyClient, err := scanProxy.NewClientWithResponses(participant.Endpoints.ValidatorAPIURL, scanProxy.WithRequestEditorFn(interceptor))
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to create scan proxy client: %w", err)
	}
	tokenMetadataClient, err := tokenMetadataV1.NewClientWithResponses(
		fmt.Sprintf("%s/v0/scan-proxy", participant.Endpoints.ValidatorAPIURL),
		tokenMetadataV1.WithRequestEditorFn(interceptor),
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to create token metadata client: %w", err)
	}
	transferInstructionClient, err := transferInstructionV1.NewClientWithResponses(
		fmt.Sprintf("%s/v0/scan-proxy", participant.Endpoints.ValidatorAPIURL),
		transferInstructionV1.WithRequestEditorFn(interceptor),
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to create transfer instruction client: %w", err)
	}

	// Get registry admin
	registryInfoResponse, err := tokenMetadataClient.GetRegistryInfoWithResponse(ctx)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get registry info: %w", err)
	}
	if registryInfoResponse.StatusCode() != http.StatusOK {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("unexpected status code from registry info: %d", registryInfoResponse.StatusCode())
	}
	registryAdmin := registryInfoResponse.JSON200.AdminId

	// Ensure FeeQuoter has Amulet configured and priced (otherwise Send fails at FinalizeFee).
	// This mirrors the reference CCIP send e2e test flow.
	disclosedFeeQuoter, disclosedContracts, err = ensureAmuletFeeTokenConfiguredAndPriced(
		ctx,
		participant,
		feeQuoterAddress,
		disclosedFeeQuoter,
		disclosedContracts,
		registryAdmin,
		participant.PartyID,
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, err
	}

	// Get transfer factory for Amulet tokens (sender to CCIP owner)
	// Get CCIP owner party from the first participant (usually the CCIP participant)
	ccipOwnerParty := participant.PartyID
	if len(c.chain.Participants) > 0 {
		// Use the first participant as CCIP owner (this might need adjustment based on actual setup)
		ccipOwnerParty = c.chain.Participants[0].PartyID
	}
	transferFactoryResponse, err := transferInstructionClient.GetTransferFactoryWithResponse(ctx, transferInstructionV1.GetFactoryRequest{
		ChoiceArguments: map[string]any{
			"expectedAdmin": registryAdmin,
			"transfer": map[string]any{
				"sender":   senderParty,
				"receiver": ccipOwnerParty,
				"amount":   "100.00",
				"instrumentId": map[string]any{
					"admin": registryAdmin,
					"id":    "Amulet",
				},
				"lock":             nil,
				"requestedAt":      time.Now().Add(-time.Hour).Format(time.RFC3339),
				"executeBefore":    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"inputHoldingCids": []string{},
				"meta": map[string]any{
					"values": map[string]any{},
				},
			},
			"extraArgs": map[string]any{
				"context": map[string]any{
					"values": map[string]any{},
				},
				"meta": map[string]any{
					"values": map[string]any{},
				},
			},
		},
		ExcludeDebugFields: nil,
	})
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get transfer factory: %w", err)
	}
	if transferFactoryResponse.StatusCode() != http.StatusOK {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("unexpected status code from transfer factory: %d", transferFactoryResponse.StatusCode())
	}
	transferFactoryCid := transferFactoryResponse.JSON200.FactoryId
	// Strip "0x" prefix if present
	transferFactoryCid = strings.TrimPrefix(transferFactoryCid, "0x")
	transferFactoryCid = strings.TrimPrefix(transferFactoryCid, "0X")

	// Get choice context from transfer factory response
	choiceContextData := transferFactoryResponse.JSON200.ChoiceContext.ChoiceContextData
	choiceContext, err := choiceContextFromData(choiceContextData)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to convert choice context: %w", err)
	}

	// Get disclosed contracts from transfer factory response
	var transferFactoryDisclosures []*apiv2.DisclosedContract
	for _, contract := range transferFactoryResponse.JSON200.ChoiceContext.DisclosedContracts {
		templateId, err := templateIdFromString(contract.TemplateId)
		if err != nil {
			return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to parse template id: %w", err)
		}
		createdEventBlob, err := base64.StdEncoding.DecodeString(contract.CreatedEventBlob)
		if err != nil {
			return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to decode created event blob: %w", err)
		}
		transferFactoryDisclosures = append(transferFactoryDisclosures, &apiv2.DisclosedContract{
			TemplateId:       templateId,
			ContractId:       contract.ContractId,
			CreatedEventBlob: createdEventBlob,
			SynchronizerId:   contract.SynchronizerId,
		})
	}
	disclosedContracts = append(disclosedContracts, transferFactoryDisclosures...)

	// Mint Amulet tokens to sender so they can pay the fee
	feeTokenHoldingCid, err := mintAMT(ctx, participant, tokenMetadataClient, transferInstructionClient, scanProxyClient, senderParty, "100.00")
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to mint AMT to sender: %w", err)
	}
	disclosedFeeTokenHolding, err := getDisclosedContractById(ctx, participant, feeTokenHoldingCid)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get disclosed fee token holding: %w", err)
	}
	disclosedContracts = append(disclosedContracts, disclosedFeeTokenHolding)

	// Get disclosed CommitteeVerifier contract for CCV send inputs
	// For now, use the first CCV (the reference uses a single CCV)
	var disclosedCCV *apiv2.DisclosedContract
	var ccvRawAddr string
	if len(disclosedCCVs) > 0 {
		disclosedCCV = disclosedCCVs[0]
		// Get the raw address for the CCV - try to get from datastore labels first
		ccvRef, err := c.e.DataStore.Addresses().Get(
			datastore.NewAddressRefKey(
				c.chainDetails.ChainSelector,
				datastore.ContractType(committee_verifier.ContractType),
				committee_verifier.Version,
				devenvcommon.DefaultCommitteeVerifierQualifier,
			),
		)
		if err == nil && len(ccvRef.Labels.List()) > 0 {
			// Raw address is stored in Labels
			ccvRawAddr = ccvRef.Labels.List()[0]
		} else {
			// Fallback: construct from instance address (format: instance-id@party-id)
			// For now, use the hex representation as a placeholder
			ccvRawAddr = ccvInstanceAddresses[0].Hex()
		}
	} else {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("no CCV disclosed contracts found")
	}

	// Strip "0x" prefix from transferFactoryCid if present (Canton contract IDs shouldn't have it, but be safe)
	transferFactoryCid = strings.TrimPrefix(transferFactoryCid, "0x")
	transferFactoryCid = strings.TrimPrefix(transferFactoryCid, "0X")

	// Build command arguments manually using apiv2.Value structures (like ccip_execute_token_test.go)
	// Use choiceContext directly as apiv2.Value to preserve the structure
	var emptyMetadata = &apiv2.Value{Sum: &apiv2.Value_Record{Record: &apiv2.Record{Fields: []*apiv2.RecordField{
		{
			Label: "values",
			Value: &apiv2.Value{Sum: &apiv2.Value_TextMap{TextMap: &apiv2.TextMap{Entries: nil}}},
		},
	}}}}

	// Build feeTokenHoldingCids list
	var feeTokenHoldingCids []*apiv2.Value
	if feeTokenHoldingCid != "" {
		feeTokenHoldingCids = []*apiv2.Value{
			{Sum: &apiv2.Value_ContractId{ContractId: feeTokenHoldingCid}},
		}
	}

	// Build FeeToken InstrumentId
	feeTokenInstrumentIdValue := &apiv2.Value{Sum: &apiv2.Value_Record{Record: &apiv2.Record{Fields: []*apiv2.RecordField{
		{Label: "admin", Value: &apiv2.Value{Sum: &apiv2.Value_Party{Party: registryAdmin}}},
		{Label: "id", Value: &apiv2.Value{Sum: &apiv2.Value_Text{Text: "Amulet"}}},
	}}}}

	// print all the cids
	c.logger.Debug().Msgf("routerCid: %s", routerCid)
	c.logger.Debug().Msgf("onRampCid: %s", disclosedOnRamp.GetContractId())
	c.logger.Debug().Msgf("globalConfigCid: %s", disclosedGlobalConfig.GetContractId())
	c.logger.Debug().Msgf("tokenAdminRegistryCid: %s", disclosedTAR.GetContractId())
	c.logger.Debug().Msgf("rmnRemoteCid: %s", disclosedRMNRemote.GetContractId())
	c.logger.Debug().Msgf("feeQuoterCid: %s", disclosedFeeQuoter.GetContractId())
	c.logger.Debug().Msgf("feeTokenHoldingCid: %s", feeTokenHoldingCid)

	// Build ccipSendArgs matching the reference structure exactly (inline, not using fields array)
	ccipSendArgs := &apiv2.Value{Sum: &apiv2.Value_Record{Record: &apiv2.Record{Fields: []*apiv2.RecordField{
		{Label: "routerCid", Value: &apiv2.Value{Sum: &apiv2.Value_ContractId{ContractId: routerCid}}},
		{Label: "onRampCid", Value: &apiv2.Value{Sum: &apiv2.Value_ContractId{ContractId: disclosedOnRamp.GetContractId()}}},
		{Label: "globalConfigCid", Value: &apiv2.Value{Sum: &apiv2.Value_ContractId{ContractId: disclosedGlobalConfig.GetContractId()}}},
		{Label: "tokenAdminRegistryCid", Value: &apiv2.Value{Sum: &apiv2.Value_ContractId{ContractId: disclosedTAR.GetContractId()}}},
		{Label: "rmnRemoteCid", Value: &apiv2.Value{Sum: &apiv2.Value_ContractId{ContractId: disclosedRMNRemote.GetContractId()}}},
		{Label: "feeQuoterCid", Value: &apiv2.Value{Sum: &apiv2.Value_ContractId{ContractId: disclosedFeeQuoter.GetContractId()}}},
		{Label: "destChainSelector", Value: &apiv2.Value{Sum: &apiv2.Value_Numeric{Numeric: strconv.FormatUint(dest, 10)}}},
		{Label: "receiver", Value: &apiv2.Value{Sum: &apiv2.Value_Text{Text: hex.EncodeToString(fields.Receiver)}}},
		{Label: "payload", Value: &apiv2.Value{Sum: &apiv2.Value_Text{Text: hex.EncodeToString(fields.Data)}}},
		{Label: "ccipReceiveGasLimit", Value: &apiv2.Value{Sum: &apiv2.Value_Int64{Int64: int64(opts.ExecutionGasLimit)}}},
		{Label: "senderRequiredCCVs", Value: &apiv2.Value{Sum: &apiv2.Value_List{List: &apiv2.List{Elements: nil}}}},
		{Label: "feeToken", Value: feeTokenInstrumentIdValue},
		{Label: "feeTokenInput", Value: &apiv2.Value{Sum: &apiv2.Value_Record{Record: &apiv2.Record{Fields: []*apiv2.RecordField{
			{Label: "transferFactory", Value: &apiv2.Value{Sum: &apiv2.Value_ContractId{ContractId: transferFactoryCid}}},
			{Label: "extraArgs", Value: &apiv2.Value{Sum: &apiv2.Value_Record{Record: &apiv2.Record{Fields: []*apiv2.RecordField{
				{Label: "context", Value: choiceContext},
				{Label: "meta", Value: emptyMetadata},
			}}}}},
			{Label: "tokenPoolHoldings", Value: &apiv2.Value{Sum: &apiv2.Value_List{List: &apiv2.List{Elements: nil}}}},
		}}}}},
		{Label: "feeTokenHoldingCids", Value: &apiv2.Value{Sum: &apiv2.Value_List{List: &apiv2.List{Elements: feeTokenHoldingCids}}}},
		{Label: "tokenTransfer", Value: &apiv2.Value{Sum: &apiv2.Value_Optional{Optional: &apiv2.Optional{}}}},
		{Label: "ccvSendInputs", Value: &apiv2.Value{Sum: &apiv2.Value_List{List: &apiv2.List{Elements: []*apiv2.Value{
			{Sum: &apiv2.Value_Record{Record: &apiv2.Record{Fields: []*apiv2.RecordField{
				{Label: "ccvCid", Value: &apiv2.Value{Sum: &apiv2.Value_ContractId{ContractId: disclosedCCV.GetContractId()}}},
				{Label: "ccvRawAddress", Value: rawInstanceAddress(ccvRawAddr)},
				{Label: "verifierArgs", Value: &apiv2.Value{Sum: &apiv2.Value_Text{Text: ""}}},
			}}}},
		}}}}},
	}}}}

	// Submit transaction to call CCIPSender.Send
	res, err := participant.LedgerServices.Command.SubmitAndWaitForTransaction(ctx, &apiv2.SubmitAndWaitForTransactionRequest{
		Commands: &apiv2.Commands{
			CommandId: uuid.New().String(),
			Commands: []*apiv2.Command{
				{
					Command: &apiv2.Command_Exercise{
						Exercise: &apiv2.ExerciseCommand{
							TemplateId: &apiv2.Identifier{
								PackageId:  "#ccip-sender",
								ModuleName: "CCIP.CCIPSender",
								EntityName: "CCIPSender",
							},
							ContractId:     ccipSenderCid,
							Choice:         "Send",
							ChoiceArgument: ccipSendArgs,
						},
					},
				},
			},
			ActAs:              []string{senderParty},
			DisclosedContracts: disclosedContracts,
		},
	})
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to submit CCIPSender.Send transaction: %w", err)
	}

	// Extract CCIPMessageSent event from the transaction
	for _, event := range res.GetTransaction().GetEvents() {
		if e, ok := event.GetEvent().(*apiv2.Event_Created); ok {
			// Check if this is a CCIPMessageSent event
			// The template ID should match the source reader's template ID
			templateID := e.Created.GetTemplateId()
			if templateID.GetEntityName() == "CCIPMessageSent" {
				// Parse the event to extract message details
				// The event structure is: CCIPMessageSent with fields: ccipOwner, sender, observers, event
				// The "event" field contains: destChainSelector, sequenceNumber, messageId, encodedMessage, verifierBlobs, receipts
				fields := e.Created.GetCreateArguments().GetFields()
				for _, field := range fields {
					if field.GetLabel() == "event" {
						eventRecord := field.GetValue().GetRecord()
						if eventRecord != nil {
							// Extract message details from the event
							var extractedMessageID [32]byte
							var decodedMessage *protocol.Message
							var messageIDFound bool
							var verifierBlobs [][]byte
							var receiptIssuers []protocol.UnknownAddress

							for _, eventField := range eventRecord.GetFields() {
								switch eventField.GetLabel() {
								case "messageId":
									messageIDText := eventField.GetValue().GetText()
									messageIDBytes, err := hex.DecodeString(messageIDText)
									if err == nil {
										copy(extractedMessageID[:], messageIDBytes)
										messageIDFound = true
									}
								case "encodedMessage":
									// Decode the message from the event to get the actual sequence number
									// The encodedMessage contains the actual message that was sent on-chain
									encodedMessageText := eventField.GetValue().GetText()
									encodedMessageBytes, err := hex.DecodeString(encodedMessageText)
									if err == nil {
										decodedMsg, err := protocol.DecodeMessage(encodedMessageBytes)
										if err == nil {
											decodedMessage = decodedMsg
										}
									}
								case "verifierBlobs":
									// Extract verifier blobs from the event
									if list := eventField.GetValue().GetList(); list != nil {
										for _, blobElem := range list.GetElements() {
											blobText := blobElem.GetText()
											blobBytes, err := hex.DecodeString(blobText)
											if err == nil {
												verifierBlobs = append(verifierBlobs, blobBytes)
											}
										}
									}
								case "receipts":
									// Extract receipts from the event
									// Receipts contain issuer addresses that are needed for verification
									if list := eventField.GetValue().GetList(); list != nil {
										for _, receiptElem := range list.GetElements() {
											if receiptRecord := receiptElem.GetRecord(); receiptRecord != nil {
												// Extract issuerAddress from each receipt
												for _, receiptField := range receiptRecord.GetFields() {
													if receiptField.GetLabel() == "issuerAddress" {
														issuerText := receiptField.GetValue().GetText()
														issuerAddr, err := protocol.NewUnknownAddressFromHex(issuerText)
														if err == nil {
															receiptIssuers = append(receiptIssuers, issuerAddr)
														}
														break // Only need issuerAddress from each receipt
													}
												}
											}
										}
									}
								}
							}

							if messageIDFound {
								// Use the decoded message from the event if available, otherwise fall back to the created message
								messageToReturn := msg
								if decodedMessage != nil {
									messageToReturn = decodedMessage
								}

								return cciptestinterfaces.MessageSentEvent{
									MessageID:      extractedMessageID,
									Sender:         protocol.UnknownAddress{}, // TODO: extract from event
									Message:        messageToReturn,
									ReceiptIssuers: receiptIssuers,
									VerifierBlobs:  verifierBlobs,
								}, nil
							}
						}
					}
				}
			}
		}
	}

	// If we didn't find the event, return error
	return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("CCIPMessageSent event not found in transaction response")
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
	if len(c.chain.Participants) == 0 {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("canton chain not properly initialized: no participants available")
	}

	participant := c.chain.Participants[0]
	ccipOwnerParty := participant.PartyID

	// Use stored source reader configuration
	grpcURL := c.sourceReaderGRPCURL
	jwt := c.sourceReaderJWT
	templateID := c.sourceReaderTemplateID

	// If config is not stored, we cannot proceed
	if grpcURL == "" || jwt == "" || templateID == "" {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf(
			"WaitOneSentEventBySeqNo: missing Canton source reader configuration. "+
				"Required: grpcURL=%q, jwt=%q, templateID=%q. "+
				"The Chain must be created with source reader configuration via NewWithConfig. "+
				"See build/devenv/tests/integration/canton/source_reader_test.go for an example",
			grpcURL != "", jwt != "", templateID != "",
		)
	}

	// Convert zerolog.Logger to chainlink-common logger.Logger
	// Create a logger using the development config
	// TODO: Use proper logger adapter when available
	commonLogger, err := logger.New()
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to create logger: %w", err)
	}
	commonLogger = logger.Named(commonLogger, "canton-wait-sent-event")

	sourceReader, err := cantonSourceReader.NewSourceReader(
		commonLogger,
		grpcURL,
		jwt,
		cantonSourceReader.ReaderConfig{
			CCIPOwnerParty:            ccipOwnerParty,
			CCIPMessageSentTemplateID: templateID,
		},
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to create Canton source reader: %w", err)
	}

	// Poll for events matching the destination chain selector and sequence number
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Get initial block state to know where to start polling
	initialLatest, initialFinalized, err := sourceReader.LatestAndFinalizedBlock(ctx)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get initial block state: %w", err)
	}

	// Start polling from a few blocks before finalized to catch events that might have been emitted
	// Use finalized - 10 blocks, or 0 if that would be negative
	startBlock := int64(initialFinalized.Number)
	if startBlock > 10 {
		startBlock -= 10
	} else {
		startBlock = 0
	}
	lastBlock := big.NewInt(startBlock)

	c.logger.Info().
		Uint64("destChainSelector", to).
		Uint64("sequenceNumber", seq).
		Uint64("startBlock", uint64(startBlock)).
		Uint64("initialFinalized", initialFinalized.Number).
		Uint64("initialLatest", initialLatest.Number).
		Msg("Starting to poll for message sent event")

	for {
		select {
		case <-ctx.Done():
			return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("timeout waiting for message sent event: %w", ctx.Err())
		case <-ticker.C:
			// Get latest and finalized blocks
			latest, _, err := sourceReader.LatestAndFinalizedBlock(ctx)
			if err != nil {
				c.logger.Warn().Err(err).Msg("Failed to get latest/finalized blocks, retrying")
				continue
			}

			// Fetch events from lastBlock to latest
			// Note: FetchMessageSentEvents uses inclusive end, so we query up to latest
			toBlock := big.NewInt(int64(latest.Number))
			if lastBlock.Cmp(toBlock) > 0 {
				// Nothing new to query yet.
				continue
			}

			c.logger.Debug().
				Uint64("fromBlock", lastBlock.Uint64()).
				Uint64("toBlock", toBlock.Uint64()).
				Msg("Fetching message sent events")

			events, err := sourceReader.FetchMessageSentEvents(ctx, lastBlock, toBlock)
			if err != nil {
				c.logger.Warn().Err(err).Msg("Failed to fetch message sent events, retrying")
				continue
			}

			c.logger.Debug().
				Int("eventCount", len(events)).
				Msg("Fetched message sent events")

			// Filter events by destination chain selector and sequence number
			for _, event := range events {
				c.logger.Debug().
					Uint64("eventDestChainSelector", uint64(event.Message.DestChainSelector)).
					Uint64("eventSequenceNumber", uint64(event.Message.SequenceNumber)).
					Str("messageID", event.MessageID.String()).
					Msg("Checking event")
				if event.Message.DestChainSelector == protocol.ChainSelector(to) &&
					event.Message.SequenceNumber == protocol.SequenceNumber(seq) {
					c.logger.Info().
						Str("messageID", event.MessageID.String()).
						Msg("Found matching message sent event")
					// Convert protocol.MessageSentEvent to cciptestinterfaces.MessageSentEvent
					return convertToTestInterfaceEvent(event), nil
				}
			}

			// Update lastBlock for next iteration (use toBlock + 1 to avoid re-fetching the same block)
			lastBlock = new(big.Int).Add(toBlock, big.NewInt(1))
		}
	}
}

// convertToTestInterfaceEvent converts a protocol.MessageSentEvent to cciptestinterfaces.MessageSentEvent
func convertToTestInterfaceEvent(event protocol.MessageSentEvent) cciptestinterfaces.MessageSentEvent {
	// Extract ReceiptIssuers and VerifierBlobs from Receipts
	receiptIssuers := make([]protocol.UnknownAddress, 0, len(event.Receipts))
	verifierBlobs := make([][]byte, 0, len(event.Receipts))

	for _, receipt := range event.Receipts {
		// ReceiptIssuers are the issuer addresses from receipts
		// The issuer is stored in the receipt, but we need to extract it
		// For now, we'll extract from the receipt's issuer field if available
		// Note: The exact structure depends on how receipts are stored
		if len(receipt.Issuer) > 0 {
			receiptIssuers = append(receiptIssuers, receipt.Issuer)
		}
		if len(receipt.Blob) > 0 {
			verifierBlobs = append(verifierBlobs, receipt.Blob)
		}
	}

	return cciptestinterfaces.MessageSentEvent{
		MessageID:      [32]byte(event.MessageID),
		Sender:         protocol.UnknownAddress{}, // TODO: extract sender from event if available
		Message:        &event.Message,
		ReceiptIssuers: receiptIssuers,
		VerifierBlobs:  verifierBlobs,
	}
}

// deployOrGetCCIPSender deploys a CCIPSender contract for the given party, or returns the existing one.
// It returns the contract ID, created event blob, and template ID of the CCIPSender.
// Note: CCIPSender DAR must be uploaded during DeployContractsForSelector before calling this function.
func (c *Chain) deployOrGetCCIPSender(ctx context.Context, partyID string) (string, []byte, *apiv2.Identifier, error) {
	participant := c.chain.Participants[0]

	// Fixed instance ID for the sender, this makes it deterministic
	instanceID := "test-ccipsender"

	// Try to create the CCIPSender contract
	// If it already exists, we'll get an error but that's okay - we'll try to find it
	res, err := participant.LedgerServices.Command.SubmitAndWaitForTransaction(ctx, &apiv2.SubmitAndWaitForTransactionRequest{
		Commands: &apiv2.Commands{
			CommandId: uuid.New().String(),
			Commands: []*apiv2.Command{
				{
					Command: &apiv2.Command_Create{
						Create: &apiv2.CreateCommand{
							TemplateId: &apiv2.Identifier{
								PackageId:  "#ccip-sender",
								ModuleName: "CCIP.CCIPSender",
								EntityName: "CCIPSender",
							},
							CreateArguments: &apiv2.Record{
								Fields: []*apiv2.RecordField{
									{
										Label: "instanceId",
										Value: &apiv2.Value{
											Sum: &apiv2.Value_Text{
												Text: instanceID,
											},
										},
									},
									{
										Label: "owner",
										Value: &apiv2.Value{
											Sum: &apiv2.Value_Party{
												Party: partyID,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			ActAs: []string{partyID},
		},
	})

	if err != nil {
		// If creation failed, try to find existing contract by scanning
		// For now, we'll return an error - in a production system we'd scan for existing contracts
		return "", nil, nil, fmt.Errorf("failed to create CCIPSender (it may already exist): %w", err)
	}

	// Get the update with created event blob included
	updateRes, err := participant.LedgerServices.Update.GetUpdateById(ctx, &apiv2.GetUpdateByIdRequest{
		UpdateId: res.GetTransaction().GetUpdateId(),
		UpdateFormat: &apiv2.UpdateFormat{
			IncludeTransactions: &apiv2.TransactionFormat{
				TransactionShape: apiv2.TransactionShape_TRANSACTION_SHAPE_ACS_DELTA,
				EventFormat: &apiv2.EventFormat{
					FiltersByParty: map[string]*apiv2.Filters{
						partyID: {
							Cumulative: []*apiv2.CumulativeFilter{
								{
									IdentifierFilter: &apiv2.CumulativeFilter_WildcardFilter{
										WildcardFilter: &apiv2.WildcardFilter{
											IncludeCreatedEventBlob: true,
										},
									},
								},
							},
						},
					},
					Verbose: true,
				},
			},
		},
	})
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to get update with created event blob: %w", err)
	}

	// Extract contract ID, created event blob, and template ID from the created event
	for _, event := range updateRes.GetTransaction().GetEvents() {
		if e, ok := event.GetEvent().(*apiv2.Event_Created); ok {
			if e.Created.GetTemplateId().GetEntityName() == "CCIPSender" {
				blob := e.Created.GetCreatedEventBlob()
				if len(blob) == 0 {
					return "", nil, nil, fmt.Errorf("created event blob is empty for CCIPSender contract")
				}
				// Use the actual TemplateId from the created event (this has the real package ID without '#')
				return e.Created.GetContractId(), blob, e.Created.GetTemplateId(), nil
			}
		}
	}

	return "", nil, nil, fmt.Errorf("CCIPSender was created but contract ID not found in transaction events")
}

// rawInstanceAddress converts a string to an apiv2.Value_Record for CCIP `common.RawInstanceAddress`.
//
// In the generated bindings (`chainlink-canton/bindings/generated/ccip/common`), RawInstanceAddress is
// a record with a single non-optional field named "unpack" (NOT "rawAddress").
// If we send the wrong field name, the ledger fails command preprocessing with:
//
//	Missing non-optional field "unpack"
func rawInstanceAddress(addr string) *apiv2.Value {
	return &apiv2.Value{
		Sum: &apiv2.Value_Record{
			Record: &apiv2.Record{
				Fields: []*apiv2.RecordField{
					{
						Label: "unpack",
						Value: &apiv2.Value{
							Sum: &apiv2.Value_Text{
								Text: addr,
							},
						},
					},
				},
			},
		},
	}
}

// choiceContextFromData converts the choice context data from the API response to apiv2.Value
func choiceContextFromData(choiceContextData map[string]any) (*apiv2.Value, error) {
	values, ok := choiceContextData["values"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no values found in choice context")
	}

	var fields []*apiv2.TextMap_Entry
	for k, v := range values {
		f, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("value is not a map: %T", v)
		}
		tag, ok := f["tag"].(string)
		if !ok {
			return nil, fmt.Errorf("tag is not a string: %T", f["tag"])
		}
		rawValue := f["value"]

		var value *apiv2.Value
		switch tag {
		case "AV_ContractId":
			valueString, ok := rawValue.(string)
			if !ok {
				return nil, fmt.Errorf("AV_ContractId value is not a string: %T", rawValue)
			}
			value = &apiv2.Value{Sum: &apiv2.Value_ContractId{ContractId: valueString}}
		case "AV_Bool":
			valueBool, ok := rawValue.(bool)
			if !ok {
				return nil, fmt.Errorf("AV_Bool value is not a bool: %T", rawValue)
			}
			value = &apiv2.Value{Sum: &apiv2.Value_Bool{Bool: valueBool}}
		case "AV_Int":
			// JSON numbers come as float64
			valueFloat, ok := rawValue.(float64)
			if !ok {
				return nil, fmt.Errorf("AV_Int value is not a number: %T", rawValue)
			}
			value = &apiv2.Value{Sum: &apiv2.Value_Int64{Int64: int64(valueFloat)}}
		case "AV_Text":
			valueString, ok := rawValue.(string)
			if !ok {
				return nil, fmt.Errorf("AV_Text value is not a string: %T", rawValue)
			}
			value = &apiv2.Value{Sum: &apiv2.Value_Text{Text: valueString}}
		default:
			return nil, fmt.Errorf("unimplemented tag: %v", tag)
		}

		fields = append(fields, &apiv2.TextMap_Entry{
			Key: k,
			Value: &apiv2.Value{Sum: &apiv2.Value_Variant{Variant: &apiv2.Variant{
				Constructor: tag,
				Value:       value,
			}}},
		})
	}

	return &apiv2.Value{Sum: &apiv2.Value_Record{Record: &apiv2.Record{Fields: []*apiv2.RecordField{
		{
			Label: "values",
			Value: &apiv2.Value{Sum: &apiv2.Value_TextMap{TextMap: &apiv2.TextMap{Entries: fields}}},
		},
	}}}}, nil
}

// templateIdFromString parses a template ID string (e.g., "#ccip-sender:CCIP.CCIPSender:CCIPSender") into apiv2.Identifier
func templateIdFromString(templateIdStr string) (*apiv2.Identifier, error) {
	// Template ID format: "#package-id:ModuleName:EntityName"
	//
	// IMPORTANT: do NOT strip the leading '#'. In this repo/test setup we rely on
	// Canton/Daml package-id aliases like "#ccip-sender" (see integration tests).
	// Stripping '#' turns it into an invalid/different package-id ("ccip-sender"),
	// which can lead to confusing command-preprocessing errors (e.g. missing/extra fields).
	parts := strings.Split(templateIdStr, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid template ID format: %s", templateIdStr)
	}
	return &apiv2.Identifier{
		PackageId:  parts[0],
		ModuleName: parts[1],
		EntityName: parts[2],
	}, nil
}

func getCurrentOffset(ctx context.Context, stateService apiv2.StateServiceClient) (int64, error) {
	ledgerEndResp, err := stateService.GetLedgerEnd(ctx, &apiv2.GetLedgerEndRequest{})
	if err != nil {
		return 0, fmt.Errorf("failed to get ledger end: %w", err)
	}
	return ledgerEndResp.GetOffset(), nil
}

func getDisclosedContractById(ctx context.Context, participant canton.Participant, contractId string) (*apiv2.DisclosedContract, error) {
	offset, err := getCurrentOffset(ctx, participant.LedgerServices.State)
	if err != nil {
		return nil, err
	}

	activeContractsResponse, err := participant.LedgerServices.State.GetActiveContracts(ctx, &apiv2.GetActiveContractsRequest{
		ActiveAtOffset: offset,
		EventFormat: &apiv2.EventFormat{
			FiltersByParty: map[string]*apiv2.Filters{
				participant.PartyID: {
					Cumulative: []*apiv2.CumulativeFilter{
						{
							IdentifierFilter: &apiv2.CumulativeFilter_WildcardFilter{
								WildcardFilter: &apiv2.WildcardFilter{
									IncludeCreatedEventBlob: true,
								},
							},
						},
					},
				},
			},
			Verbose: false,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get active contracts using wildcard filter: %w", err)
	}
	defer activeContractsResponse.CloseSend()
	for {
		activeContract, err := activeContractsResponse.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to receive active contracts: %w", err)
		}
		if c, ok := activeContract.GetContractEntry().(*apiv2.GetActiveContractsResponse_ActiveContract); ok {
			if c.ActiveContract.GetCreatedEvent().ContractId == contractId {
				return &apiv2.DisclosedContract{
					TemplateId:       c.ActiveContract.GetCreatedEvent().GetTemplateId(),
					ContractId:       c.ActiveContract.GetCreatedEvent().GetContractId(),
					CreatedEventBlob: c.ActiveContract.GetCreatedEvent().GetCreatedEventBlob(),
					SynchronizerId:   c.ActiveContract.GetSynchronizerId(),
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to find active contract with id %s", contractId)
}

func getAmuletRulesContract(ctx context.Context, scanProxyClient scanProxy.ClientWithResponsesInterface) (string, *apiv2.Identifier, error) {
	amuletRulesResponse, err := scanProxyClient.GetAmuletRulesWithResponse(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("error getting amulet rules response: %w", err)
	}
	if amuletRulesResponse.StatusCode() != http.StatusOK {
		return "", nil, fmt.Errorf("unexpected status code: %d: %v", amuletRulesResponse.StatusCode(), amuletRulesResponse.Body)
	}
	amuletRulesId, err := templateIdFromString(amuletRulesResponse.JSON200.AmuletRules.Contract.TemplateId)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse amulet rules template id: %w", err)
	}
	return amuletRulesResponse.JSON200.AmuletRules.Contract.ContractId, amuletRulesId, nil
}

func getFirstOpenMiningRound(ctx context.Context, scanProxyClient scanProxy.ClientWithResponsesInterface) (string, error) {
	openMiningRoundResponse, err := scanProxyClient.GetOpenAndIssuingMiningRoundsWithResponse(ctx)
	if err != nil {
		return "", fmt.Errorf("error getting open mining rounds response: %w", err)
	}
	if openMiningRoundResponse.StatusCode() != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d: %v", openMiningRoundResponse.StatusCode(), openMiningRoundResponse.Body)
	}
	slices.SortFunc(openMiningRoundResponse.JSON200.OpenMiningRounds, func(a, b scanProxy.ContractWithState) int {
		aOpen, _ := time.Parse(time.RFC3339, a.Contract.Payload["opensAt"].(string))
		bOpen, _ := time.Parse(time.RFC3339, b.Contract.Payload["opensAt"].(string))
		return int(aOpen.UnixMilli() - bOpen.UnixMilli())
	})

	var openMiningRoundCid string
	for _, round := range openMiningRoundResponse.JSON200.OpenMiningRounds {
		opensAt, err := time.Parse(time.RFC3339, round.Contract.Payload["opensAt"].(string))
		if err != nil {
			return "", fmt.Errorf("failed to parse opensAt %q: %w", round.Contract.Payload["opensAt"], err)
		}
		targetClosesAt, err := time.Parse(time.RFC3339, round.Contract.Payload["targetClosesAt"].(string))
		if err != nil {
			return "", fmt.Errorf("failed to parse targetClosesAt %q: %w", round.Contract.Payload["targetClosesAt"], err)
		}
		if opensAt.Before(time.Now()) && targetClosesAt.After(time.Now()) {
			openMiningRoundCid = round.Contract.ContractId
		}
	}
	return openMiningRoundCid, nil
}

func mintAMT(
	ctx context.Context,
	participant canton.Participant,
	metadataClient tokenMetadataV1.ClientWithResponsesInterface,
	transferInstructionClient transferInstructionV1.ClientWithResponsesInterface,
	scanProxyClient scanProxy.ClientWithResponsesInterface,
	toParty string,
	amount string,
) (string, error) {
	// Get Instrument Admin
	registryInfoResponse, err := metadataClient.GetRegistryInfoWithResponse(ctx)
	if err != nil {
		return "", fmt.Errorf("error getting registry info: %w", err)
	}
	if registryInfoResponse.StatusCode() != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d: %v", registryInfoResponse.StatusCode(), registryInfoResponse.Body)
	}
	registryAdmin := registryInfoResponse.JSON200.AdminId

	// Get AmuletRules Contract
	amuletRulesCid, amuletRulesId, err := getAmuletRulesContract(ctx, scanProxyClient)
	if err != nil {
		return "", fmt.Errorf("failed to get amulet rules contract: %w", err)
	}

	// Create Transfer Factory (needed disclosures)
	transferFactoryResponse, err := transferInstructionClient.GetTransferFactoryWithResponse(ctx, transferInstructionV1.GetFactoryRequest{
		ChoiceArguments: map[string]any{
			"expectedAdmin": registryAdmin,
			"transfer": map[string]any{
				"sender":   registryAdmin,
				"receiver": toParty,
				"amount":   "100.00",
				"instrumentId": map[string]any{
					"admin": registryAdmin,
					"id":    "Amulet",
				},
				"lock":             nil,
				"requestedAt":      time.Now().Add(time.Hour * -1).Format(time.RFC3339),
				"executeBefore":    time.Now().Add(time.Hour * 24).Format(time.RFC3339),
				"inputHoldingCids": []string{},
				"meta": map[string]any{
					"values": map[string]any{},
				},
			},
			"extraArgs": map[string]any{
				"context": map[string]any{
					"values": map[string]any{},
				},
				"meta": map[string]any{
					"values": map[string]any{},
				},
			},
		},
		ExcludeDebugFields: nil,
	})
	if err != nil {
		return "", fmt.Errorf("error getting transferFactory response: %w", err)
	}
	if transferFactoryResponse.StatusCode() != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d: %v", transferFactoryResponse.StatusCode(), transferFactoryResponse.Body)
	}

	var disclosedContracts []*apiv2.DisclosedContract
	for _, contract := range transferFactoryResponse.JSON200.ChoiceContext.DisclosedContracts {
		id, err := templateIdFromString(contract.TemplateId)
		if err != nil {
			return "", fmt.Errorf("failed to parse template id: %w", err)
		}
		createdEventBlob, err := base64.StdEncoding.DecodeString(contract.CreatedEventBlob)
		if err != nil {
			return "", fmt.Errorf("failed to decode created event blob: %w", err)
		}
		disclosedContracts = append(disclosedContracts, &apiv2.DisclosedContract{
			TemplateId:       id,
			ContractId:       contract.ContractId,
			CreatedEventBlob: createdEventBlob,
			SynchronizerId:   contract.SynchronizerId,
		})
	}

	// Get open mining round
	openMiningRoundCid, err := getFirstOpenMiningRound(ctx, scanProxyClient)
	if err != nil {
		return "", fmt.Errorf("failed to get open mining round: %w", err)
	}

	// Mint AMT
	response, err := participant.LedgerServices.Command.SubmitAndWaitForTransaction(ctx, &apiv2.SubmitAndWaitForTransactionRequest{
		Commands: &apiv2.Commands{
			CommandId: uuid.New().String(),
			Commands: []*apiv2.Command{
				{
					Command: &apiv2.Command_Exercise{
						Exercise: &apiv2.ExerciseCommand{
							TemplateId: amuletRulesId,
							ContractId: amuletRulesCid,
							Choice:     "AmuletRules_DevNet_Tap",
							ChoiceArgument: &apiv2.Value{Sum: &apiv2.Value_Record{Record: &apiv2.Record{Fields: []*apiv2.RecordField{
								{
									Label: "receiver",
									Value: &apiv2.Value{Sum: &apiv2.Value_Party{Party: toParty}},
								}, {
									Label: "amount",
									Value: &apiv2.Value{Sum: &apiv2.Value_Numeric{Numeric: amount}},
								}, {
									Label: "openRound",
									Value: &apiv2.Value{Sum: &apiv2.Value_ContractId{ContractId: openMiningRoundCid}},
								},
							}}}},
						},
					},
				},
			},
			ActAs:              []string{toParty},
			DisclosedContracts: disclosedContracts,
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to mint AMT: %w", err)
	}

	tokenHoldingCid := ""
	for _, event := range response.GetTransaction().GetEvents() {
		if e, ok := event.GetEvent().(*apiv2.Event_Created); ok {
			// Prefer the Splice token Holding contract if present.
			if e.Created.GetTemplateId() != nil && e.Created.GetTemplateId().GetEntityName() == "Holding" {
				tokenHoldingCid = e.Created.ContractId
			} else if tokenHoldingCid == "" {
				// Fallback: keep the first created contract id, matching the testhelpers behavior.
				tokenHoldingCid = e.Created.ContractId
			}
		}
	}
	if tokenHoldingCid == "" {
		return "", fmt.Errorf("mint AMT transaction did not create any contracts")
	}
	return tokenHoldingCid, nil
}

func ensureAmuletFeeTokenConfiguredAndPriced(
	ctx context.Context,
	participant canton.Participant,
	feeQuoterAddress contracts.InstanceAddress,
	disclosedFeeQuoter *apiv2.DisclosedContract,
	disclosedContracts []*apiv2.DisclosedContract,
	registryAdmin string,
	callerParty string,
) (*apiv2.DisclosedContract, []*apiv2.DisclosedContract, error) {
	feeTokenInstrumentId := splice_api_token_holding_v1.InstrumentId{
		Admin: types.PARTY(registryAdmin),
		Id:    types.TEXT("Amulet"),
	}

	// ApplyFeeTokenUpdates: add token if missing (ignore duplicate-type errors).
	_, err := participant.LedgerServices.Command.SubmitAndWaitForTransaction(ctx, &apiv2.SubmitAndWaitForTransactionRequest{
		Commands: &apiv2.Commands{
			CommandId: uuid.New().String(),
			Commands: []*apiv2.Command{{
				Command: &apiv2.Command_Exercise{Exercise: &apiv2.ExerciseCommand{
					TemplateId: &apiv2.Identifier{PackageId: "#ccip-feequoter", ModuleName: "CCIP.FeeQuoter", EntityName: "FeeQuoter"},
					ContractId: disclosedFeeQuoter.ContractId,
					Choice:     "ApplyFeeTokenUpdates",
					ChoiceArgument: ledger.MapToValue(feequoter.ApplyFeeTokenUpdates{
						FeeTokensToRemove: []splice_api_token_holding_v1.InstrumentId{},
						FeeTokensToAdd: []feequoter.FeeTokenArgs{{
							InstrumentId:      feeTokenInstrumentId,
							PremiumMultiplier: types.NUMERIC("1.0"),
						}},
						Caller: types.PARTY(callerParty),
					}),
				}},
			}},
			ActAs:              []string{callerParty},
			DisclosedContracts: []*apiv2.DisclosedContract{disclosedFeeQuoter},
		},
	})
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "already") {
		return nil, nil, fmt.Errorf("failed to apply fee token updates: %w", err)
	}

	// Refresh FeeQuoter disclosure (choice may rotate the contract ID)
	feeQuoterActive, err2 := contract.FindActiveContractByInstanceAddress(
		ctx,
		participant.LedgerServices.State,
		participant.PartyID,
		"#ccip-feequoter:CCIP.FeeQuoter:FeeQuoter",
		feeQuoterAddress,
	)
	if err2 == nil {
		disclosedFeeQuoter = convertToDisclosedContract(feeQuoterActive)
		for i, dc := range disclosedContracts {
			if dc != nil && dc.TemplateId != nil && dc.TemplateId.EntityName == "FeeQuoter" {
				disclosedContracts[i] = disclosedFeeQuoter
				break
			}
		}
	}

	// UpdatePrices: set price for fee token
	_, err = participant.LedgerServices.Command.SubmitAndWaitForTransaction(ctx, &apiv2.SubmitAndWaitForTransactionRequest{
		Commands: &apiv2.Commands{
			CommandId: uuid.New().String(),
			Commands: []*apiv2.Command{{
				Command: &apiv2.Command_Exercise{Exercise: &apiv2.ExerciseCommand{
					TemplateId: &apiv2.Identifier{PackageId: "#ccip-feequoter", ModuleName: "CCIP.FeeQuoter", EntityName: "FeeQuoter"},
					ContractId: disclosedFeeQuoter.ContractId,
					Choice:     "UpdatePrices",
					ChoiceArgument: ledger.MapToValue(feequoter.UpdatePrices{
						PriceUpdates: feequoter.PriceUpdates{
							TokenPriceUpdates: []feequoter.TokenPriceUpdate{{
								InstrumentId: feeTokenInstrumentId,
								UsdPerToken:  types.NUMERIC("1.00"),
							}},
							GasPriceUpdates: []feequoter.GasPriceUpdate{},
						},
						Caller: types.PARTY(callerParty),
					}),
				}},
			}},
			ActAs:              []string{callerParty},
			DisclosedContracts: []*apiv2.DisclosedContract{disclosedFeeQuoter},
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to update prices for fee token: %w", err)
	}

	// Refresh again after update
	feeQuoterActive, err2 = contract.FindActiveContractByInstanceAddress(
		ctx,
		participant.LedgerServices.State,
		participant.PartyID,
		"#ccip-feequoter:CCIP.FeeQuoter:FeeQuoter",
		feeQuoterAddress,
	)
	if err2 == nil {
		disclosedFeeQuoter = convertToDisclosedContract(feeQuoterActive)
		for i, dc := range disclosedContracts {
			if dc != nil && dc.TemplateId != nil && dc.TemplateId.EntityName == "FeeQuoter" {
				disclosedContracts[i] = disclosedFeeQuoter
				break
			}
		}
	}

	return disclosedFeeQuoter, disclosedContracts, nil
}
