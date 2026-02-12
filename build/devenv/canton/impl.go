package canton

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	ledgerv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2"
	"github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2/admin"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/smartcontractkit/chainlink-canton/bindings"
	"github.com/smartcontractkit/chainlink-canton/bindings/ccip/ccipreceiver"
	ccvsBinding "github.com/smartcontractkit/chainlink-canton/bindings/ccip/ccvs"
	offramp2 "github.com/smartcontractkit/chainlink-canton/bindings/ccip/offramp"
	"github.com/smartcontractkit/chainlink-canton/bindings/ccip/perpartyrouter"
	"github.com/smartcontractkit/chainlink-canton/bindings/ccip/rmn"
	"github.com/smartcontractkit/chainlink-canton/bindings/ccip/tokenadminregistry"
	"github.com/smartcontractkit/chainlink-canton/deployment/dependencies"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/fee_quoter"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/global_config"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/offramp"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/onramp"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/per_party_router_factory"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/receiver"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/token_admin_registry"
	"github.com/smartcontractkit/chainlink-canton/deployment/utils/operations/contract"
	evmadapters "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	dsutils "github.com/smartcontractkit/chainlink-ccip/deployment/utils/datastore"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	cantonadapters "github.com/smartcontractkit/chainlink-ccv/devenv/canton/adapters"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/canton"
	"github.com/smartcontractkit/go-daml/pkg/client"
	"github.com/smartcontractkit/go-daml/pkg/types"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-canton/bindings/ccip/ccvs"
	"github.com/smartcontractkit/chainlink-canton/bindings/ccip/common"
	"github.com/smartcontractkit/chainlink-canton/contracts"
	cantonChangesets "github.com/smartcontractkit/chainlink-canton/deployment/changesets"
	"github.com/smartcontractkit/chainlink-canton/deployment/sequences"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
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

	helper *Helper
}

func New(ctx context.Context, logger zerolog.Logger, e *deployment.Environment, chainID string) (*Chain, error) {
	chainDetails, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyCanton)
	if err != nil {
		return nil, fmt.Errorf("get chain details for chain %s: %w", chainID, err)
	}
	chain := e.BlockChains.CantonChains()[chainDetails.ChainSelector]
	jwt, err := chain.Participants[0].JWTProvider.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT token: %w", err)
	}
	h, err := NewHelperFromBlockchainInput(ctx, chain.Participants[0].Endpoints.GRPCLedgerAPIURL, jwt)
	if err != nil {
		return nil, fmt.Errorf("failed to create helper: %w", err)
	}

	return &Chain{
		e:            e,
		chain:        chain,
		chainDetails: chainDetails,
		logger:       logger,
		helper:       h,
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
	// Deploy the json-tests DAR so that it's available on the network.
	// NOTE: this is hacky, but temporary, until we deploy the real CCIP contracts.
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	darPath := filepath.Join(dir, "../tests/integration/canton/json-tests-0.0.1.dar")
	err := c.helper.UploadDar(ctx, darPath)
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

	chain := env.BlockChains.CantonChains()[selector]
	token, err := chain.Participants[0].JWTProvider.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT token: %w", err)
	}

	// Get Primary Party
	bindingClient, err := client.NewDamlClient(token, chain.Participants[0].Endpoints.GRPCLedgerAPIURL).
		WithAdminAddress(chain.Participants[0].Endpoints.AdminAPIURL).
		Build(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Daml binding client: %w", err)
	}
	defer bindingClient.Close()

	user, err := bindingClient.UserMng.GetUser(ctx, c.helper.GetUserID())
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	l.Info().Msg("Uploading and vetting CCIP DARs...")
	commonDar, err := contracts.GetDar(contracts.CCIPCommon, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get common dar file")
	}
	err = bindingClient.PackageMng.UploadDarFile(ctx, commonDar, "")
	if err != nil {
		return nil, fmt.Errorf("failed to upload common dar file")
	}
	offRampDar, err := contracts.GetDar(contracts.CCIPOffRamp, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get offramp dar file")
	}
	err = bindingClient.PackageMng.UploadDarFile(ctx, offRampDar, "")
	if err != nil {
		return nil, fmt.Errorf("failed to upload offramp dar file")
	}
	onRampDar, err := contracts.GetDar(contracts.CCIPOnRamp, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get onramp dar file")
	}
	err = bindingClient.PackageMng.UploadDarFile(ctx, onRampDar, "")
	if err != nil {
		return nil, fmt.Errorf("failed to upload onramp dar file")
	}
	tokenAdminRegistryDar, err := contracts.GetDar(contracts.CCIPTokenAdminRegistry, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get token admin registry dar file")
	}
	err = bindingClient.PackageMng.UploadDarFile(ctx, tokenAdminRegistryDar, "")
	if err != nil {
		return nil, fmt.Errorf("failed to upload token admin registry dar file")
	}
	committeeVerifierDar, err := contracts.GetDar(contracts.CCIPCommitteeVerifier, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get committee verifier dar file")
	}
	err = bindingClient.PackageMng.UploadDarFile(ctx, committeeVerifierDar, "")
	if err != nil {
		return nil, fmt.Errorf("failed to upload committee verifier dar file")
	}
	tokenPoolDar, err := contracts.GetDar(contracts.CCIPLockReleaseTokenPool, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get token pool dar file")
	}
	err = bindingClient.PackageMng.UploadDarFile(ctx, tokenPoolDar, "")
	if err != nil {
		return nil, fmt.Errorf("failed to upload token pool dar file")
	}
	perPartyRouterDar, err := contracts.GetDar(contracts.CCIPPerPartyRouter, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get per-party router dar file")
	}
	err = bindingClient.PackageMng.UploadDarFile(ctx, perPartyRouterDar, "")
	if err != nil {
		return nil, fmt.Errorf("failed to upload per-party router dar file")
	}

	l.Info().Any("selector", selector).Any("party", user.PrimaryParty).Msg("Deploying chain contracts")
	config := cantonChangesets.CantonCSDeps[cantonChangesets.DeployChainContractsConfig]{
		ChainSelector: selector,
		Participant:   0,
		UserName:      c.helper.GetUserID(),
		Party:         user.PrimaryParty,
		Config: cantonChangesets.DeployChainContractsConfig{
			Params: sequences.DeployChainContractsParams{
				CCIPOwnerParty:     user.PrimaryParty,
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
						RmnOwner:       types.PARTY(user.PrimaryParty),
						CursedSubjects: nil,
					},
				},
			},
		},
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
			storageLocation = types.TEXT("dummy-location") // TODO contracts don't allow an empty location for now
		}
		cv := sequences.CommitteeVerifierParams{
			Qualifier: qualifier,
			Template: ccvs.CommitteeVerifier{
				Owner:               types.PARTY(user.PrimaryParty), // TODO: use different ccv owner?
				InstanceId:          "",
				CcipOwner:           types.PARTY(user.PrimaryParty),
				VersionTag:          types.TEXT("49ff34ed"),
				MessageSentObserver: types.PARTY(user.PrimaryParty),
				StorageLocation:     storageLocation,
				Threshold:           types.INT64(chainCfg.Threshold),
				Signers:             signers,
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
			Address:       contracts.MustNewInstanceID("dst-token-pool-" + strconv.Itoa(i)).RawInstanceAddress(types.PARTY(user.PrimaryParty)).InstanceAddress().Hex(),
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
		Address:       contracts.MustNewInstanceID("executor-1").RawInstanceAddress(types.PARTY(user.PrimaryParty)).InstanceAddress().Hex(),
		Type:          datastore.ContractType(executor.ContractType),
		Version:       executor.Version,
		Qualifier:     devenvcommon.DefaultExecutorQualifier,
		ChainSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add executor address ref: %w", err)
	}
	err = runningDS.AddressRefStore.Add(datastore.AddressRef{
		Address:       contracts.MustNewInstanceID("executor-proxy-1").RawInstanceAddress(types.PARTY(user.PrimaryParty)).InstanceAddress().String(),
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

	chain := env.BlockChains.CantonChains()[selector]
	token, err := chain.Participants[0].JWTProvider.Token(ctx)
	if err != nil {
		return fmt.Errorf("failed to get JWT token: %w", err)
	}

	// Get Primary Party
	bindingClient, err := client.NewDamlClient(token, chain.Participants[0].Endpoints.GRPCLedgerAPIURL).
		WithAdminAddress(chain.Participants[0].Endpoints.AdminAPIURL).
		Build(ctx)
	if err != nil {
		return fmt.Errorf("failed to create Daml binding client: %w", err)
	}
	defer bindingClient.Close()

	user, err := bindingClient.UserMng.GetUser(ctx, c.helper.GetUserID())
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

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
		UserName:      c.helper.GetUserID(),
		Party:         user.PrimaryParty,
		Config: cantonChangesets.ConfigureChainForLanesConfig{
			Input: sequences.ConfigureChainForLanesInput{
				ChainSelector:      0,
				GlobalConfig:       globalConfig,
				FeeQuoter:          feeQuoter,
				OnRamp:             onRamp,
				OffRamp:            offRamp,
				CommitteeVerifiers: nil,
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
	grpcURL := bcs.Out.NetworkSpecificData.CantonEndpoints.Participants[0].GRPCLedgerAPIURL
	jwt := bcs.Out.NetworkSpecificData.CantonEndpoints.Participants[0].JWT
	h, err := NewHelperFromBlockchainInput(ctx, grpcURL, jwt)
	if err != nil {
		return nil, fmt.Errorf("failed to create helper: %w", err)
	}
	c.helper = h
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

// ManuallyExecuteMessage implements cciptestinterfaces.CCIP17.
func (c *Chain) ManuallyExecuteMessage(ctx context.Context, message protocol.Message, gasLimit uint64, ccvs []protocol.UnknownAddress, verifierResults [][]byte) (cciptestinterfaces.ExecutionStateChangedEvent, error) {
	deps := dependencies.CantonDeps{
		Chain:                c.chain,
		CommandServiceClient: c.helper.commandClient,
		StateServiceClient:   c.helper.stateServiceClient,
		Party:                c.helper.partyID,
	}

	// Create PerPartyRouter (ignore error if it exists already)
	cantonPerPartyRouterFactoryRef, err := c.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			c.chainDetails.ChainSelector,
			datastore.ContractType(per_party_router_factory.ContractType),
			per_party_router_factory.Version,
			"",
		),
	)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get canton per party router factory address ref: %w", err)
	}
	c.logger.Debug().Str("CantonPerPartyRouterFactory", cantonPerPartyRouterFactoryRef.Address).Msg("Creating per-party router factory on Canton")
	cantonPerPartyRouterFactory := contracts.HexToInstanceAddress(cantonPerPartyRouterFactoryRef.Address)

	routerInstanceID := contracts.InstanceID("test-router")
	_, _ = operations.ExecuteOperation(c.e.OperationsBundle, per_party_router_factory.CreateRouter, deps, contract.ChoiceInput[perpartyrouter.CreateRouter]{
		ChainSelector:   c.chainDetails.ChainSelector,
		InstanceAddress: cantonPerPartyRouterFactory,
		ActAs:           []string{c.helper.partyID},
		Args: perpartyrouter.CreateRouter{
			PartyOwner: types.PARTY(c.helper.partyID),
			InstanceId: types.TEXT(routerInstanceID.String()),
		},
	})
	routerAddress := routerInstanceID.RawInstanceAddress(types.PARTY(c.helper.partyID)).InstanceAddress()
	_ = routerAddress

	// Deploy receiver contract
	receiverDar, err := contracts.GetDar(contracts.CCIPReceiver, contracts.CurrentVersion)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get receiver dar: %w", err)
	}
	_, err = c.helper.pkgMgmtClient.UploadDarFile(ctx, &admin.UploadDarFileRequest{
		DarFile:       receiverDar,
		VettingChange: admin.UploadDarFileRequest_VETTING_CHANGE_VET_ALL_PACKAGES,
	})
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to upload receiver dar file: %w", err)
	}
	out, err := operations.ExecuteOperation(c.e.OperationsBundle, receiver.Deploy, deps, contract.DeployInput[ccipreceiver.CCIPReceiver]{
		ChainSelector: c.chainDetails.ChainSelector,
		Qualifier:     nil,
		ActAs:         []string{c.helper.partyID},
		Template: ccipreceiver.CCIPReceiver{
			Owner:        types.PARTY(c.helper.partyID),
			RequiredCCVs: nil,
		},
		OwnerParty: types.PARTY(c.helper.partyID),
	})
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to deploy receiver contract: %w", err)
	}
	receiverAddress := contracts.HexToInstanceAddress(out.Output.Address)

	// Resolve contracts
	receiverCid, err := contract.FindContractIDByInstanceAddress(ctx, c.e.Logger, c.helper.stateServiceClient, c.helper.partyID, ccipreceiver.CCIPReceiver{}.GetTemplateID(), receiverAddress)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get receiver contract ID: %w", err)
	}
	c.logger.Debug().Str("ReceiverAddress", receiverAddress.String()).Str("ReceiverCID", receiverCid).Msg("Resolved Receiver contract")
	_ = receiverCid

	routerCid, err := contract.FindContractIDByInstanceAddress(ctx, c.e.Logger, c.helper.stateServiceClient, c.helper.partyID, perpartyrouter.PerPartyRouter{}.GetTemplateID(), routerAddress)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get router contract ID: %w", err)
	}
	c.logger.Debug().Str("RouterAddress", routerAddress.String()).Str("RouterCID", routerCid).Msg("Resolved Router contract")

	offRampRef, err := c.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			c.chainDetails.ChainSelector,
			datastore.ContractType(offramp.ContractType),
			offramp.Version,
			"",
		),
	)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get offramp address ref: %w", err)
	}
	offRampAddress := contracts.HexToInstanceAddress(offRampRef.Address)
	offRampCid, err := contract.FindContractIDByInstanceAddress(ctx, c.e.Logger, c.helper.stateServiceClient, c.helper.partyID, offramp2.OffRamp{}.GetTemplateID(), offRampAddress)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get offramp contract ID: %w", err)
	}
	c.logger.Debug().Str("OffRampAddress", offRampAddress.String()).Str("OffRampCID", offRampCid).Msg("Resolved OffRamp contract")

	globalConfigRef, err := c.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			c.chainDetails.ChainSelector,
			datastore.ContractType(global_config.ContractType),
			global_config.Version,
			"",
		),
	)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get global config address ref: %w", err)
	}
	globalConfigAddress := contracts.HexToInstanceAddress(globalConfigRef.Address)
	globalConfigCid, err := contract.FindContractIDByInstanceAddress(ctx, c.e.Logger, c.helper.stateServiceClient, c.helper.partyID, common.GlobalConfig{}.GetTemplateID(), globalConfigAddress)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get global config contract ID: %w", err)
	}
	c.logger.Debug().Str("GlobalConfigAddress", globalConfigAddress.String()).Str("GlobalConfigCID", globalConfigCid).Msg("Resolved GlobalConfig contract")

	tokenAdminRegistryRef, err := c.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			c.chainDetails.ChainSelector,
			datastore.ContractType(token_admin_registry.ContractType),
			token_admin_registry.Version,
			"",
		),
	)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get token admin registry address ref: %w", err)
	}
	tokenAdminRegistryAddress := contracts.HexToInstanceAddress(tokenAdminRegistryRef.Address)
	tokenAdminRegistryCid, err := contract.FindContractIDByInstanceAddress(ctx, c.e.Logger, c.helper.stateServiceClient, c.helper.partyID, tokenadminregistry.TokenAdminRegistry{}.GetTemplateID(), tokenAdminRegistryAddress)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get token admin registry contract ID: %w", err)
	}
	c.logger.Debug().Str("TokenAdminRegistryAddress", tokenAdminRegistryAddress.String()).Str("TokenAdminRegistryCID", tokenAdminRegistryCid).Msg("Resolved TokenAdminRegistry contract")

	rmnRemoteRef, err := c.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			c.chainDetails.ChainSelector,
			datastore.ContractType(rmn_remote.ContractType),
			rmn_remote.Version,
			"",
		),
	)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get rmn remote address ref: %w", err)
	}
	rmnRemoteAddress := contracts.HexToInstanceAddress(rmnRemoteRef.Address)
	rmnRemoteCid, err := contract.FindContractIDByInstanceAddress(ctx, c.e.Logger, c.helper.stateServiceClient, c.helper.partyID, rmn.RMNRemote{}.GetTemplateID(), rmnRemoteAddress)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get rmn remote contract ID: %w", err)
	}
	c.logger.Debug().Str("RMNRemoteAddress", rmnRemoteAddress.String()).Str("RMNRemoteCID", rmnRemoteCid).Msg("Resolved RMNRemote contract")

	ccvAddress := contracts.HexToInstanceAddress(ccvs[0].String())
	ccvCid, err := contract.FindContractIDByInstanceAddress(ctx, c.e.Logger, c.helper.stateServiceClient, c.helper.partyID, ccvsBinding.CommitteeVerifier{}.GetTemplateID(), ccvAddress)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get ccv contract ID: %w", err)
	}
	c.logger.Debug().Str("CCVAddress", ccvAddress.String()).Str("CCVCID", ccvCid).Msg("Resolved CCV contract")

	// Execute message
	encodedMessage, err := message.Encode()
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to encode message: %w", err)
	}
	c.logger.Debug().
		Str("EncodedMessage", hex.EncodeToString(encodedMessage)).
		Str("VerifierResults", hex.EncodeToString(verifierResults[0])).
		Str("Receiver", hex.EncodeToString(message.Receiver)).
		Msg("Executing message...")

	executeOut, err := operations.ExecuteOperation(c.e.OperationsBundle, receiver.Execute, deps, contract.ChoiceInput[ccipreceiver.Execute2]{
		ChainSelector:   c.chainDetails.ChainSelector,
		InstanceAddress: receiverAddress,
		ActAs:           []string{c.helper.partyID},
		Args: ccipreceiver.Execute2{
			RouterCid:             types.CONTRACT_ID(routerCid),
			OffRampCid:            types.CONTRACT_ID(offRampCid),
			GlobalConfigCid:       types.CONTRACT_ID(globalConfigCid),
			TokenAdminRegistryCid: types.CONTRACT_ID(tokenAdminRegistryCid),
			RmnRemoteCid:          types.CONTRACT_ID(rmnRemoteCid),
			EncodedMessage:        types.TEXT(hex.EncodeToString(encodedMessage)),
			TokenTransfer:         nil,
			CcvInputs: []ccipreceiver.CCVInput{
				{
					CcvCid:          types.CONTRACT_ID(ccvCid),
					VerifierResults: types.TEXT(hex.EncodeToString(verifierResults[0])),
				},
			},
			AdditionalRequiredCCVs: nil,
		},
	})
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to execute message: %w", err)
	}
	c.logger.Debug().Str("UpdateID", executeOut.Output.ExecInfo.UpdateID).Msg("Executed message")

	// Get Update
	updateRes, err := c.helper.updatesClient.GetUpdateById(ctx, &ledgerv2.GetUpdateByIdRequest{
		UpdateId: executeOut.Output.ExecInfo.UpdateID,
		UpdateFormat: &ledgerv2.UpdateFormat{
			IncludeTransactions: &ledgerv2.TransactionFormat{
				TransactionShape: ledgerv2.TransactionShape_TRANSACTION_SHAPE_ACS_DELTA,
				EventFormat: &ledgerv2.EventFormat{
					FiltersByParty: map[string]*ledgerv2.Filters{
						c.helper.partyID: {
							Cumulative: []*ledgerv2.CumulativeFilter{
								{
									IdentifierFilter: &ledgerv2.CumulativeFilter_WildcardFilter{
										WildcardFilter: &ledgerv2.WildcardFilter{
											IncludeCreatedEventBlob: false,
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
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get update by ID: %w", err)
	}
	// Get ExecutionStateChangedEvent from events
	expectedTemplateID := perpartyrouter.ExecutionStateChanged{}.GetTemplateID()
	for _, event := range updateRes.GetTransaction().GetEvents() {
		if createdEvent := event.GetCreated(); createdEvent != nil {
			if templateId := createdEvent.GetTemplateId(); templateId != nil {
				gotTemplateId := fmt.Sprintf("#%s:%s:%s", createdEvent.GetPackageName(), templateId.GetModuleName(), templateId.GetEntityName())
				if gotTemplateId == expectedTemplateID {
					// Found the event, parse it
					c.logger.Debug().Int64("Offset", createdEvent.GetOffset()).Str("ContractId", createdEvent.GetContractId()).Msg("Found ExecutionStateChanged event")
					executionStateChanged, err := bindings.UnmarshalCreatedEvent[perpartyrouter.ExecutionStateChanged](createdEvent)
					if err != nil {
						return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to unmarshal ExecutionStateChanged event: %w", err)
					}

					// Source chain selector
					sourceChainSelectorFloat, ok := new(big.Float).SetString(string(executionStateChanged.Event.SourceChainSelector))
					if !ok {
						return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to parse source chain selector numeric, input: %s", string(executionStateChanged.Event.SourceChainSelector))
					}
					sourceChainSelector, _ := sourceChainSelectorFloat.Int(nil)
					// Message ID
					messageId, err := hex.DecodeString(string(executionStateChanged.Event.MessageId))
					if err != nil {
						return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to decode message ID %q: %w", string(executionStateChanged.Event.MessageId), err)
					}
					// Message number
					sequenceNumberFloat, ok := new(big.Float).SetString(string(executionStateChanged.Event.SequenceNumber))
					if !ok {
						return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to parse sequence number numeric, input: %s", string(executionStateChanged.Event.SequenceNumber))
					}
					sequenceNumber, _ := sequenceNumberFloat.Int(nil)
					// Execution state
					var executionState cciptestinterfaces.MessageExecutionState
					switch executionStateChanged.Event.State {
					case perpartyrouter.MessageExecutionStateUNTOUCHED:
						executionState = cciptestinterfaces.ExecutionStateUntouched
					case perpartyrouter.MessageExecutionStateIN_PROGRESS:
						executionState = cciptestinterfaces.ExecutionStateInProgress
					case perpartyrouter.MessageExecutionStateSUCCESS:
						executionState = cciptestinterfaces.ExecutionStateSuccess
					case perpartyrouter.MessageExecutionStateFAILURE:
						executionState = cciptestinterfaces.ExecutionStateFailure
					default:
						return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("unknown execution state %q", executionStateChanged.Event.State)
					}
					// Return data
					returnData, err := hex.DecodeString(string(executionStateChanged.Event.ReturnData))
					if err != nil {
						return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to decode return data %q: %w", string(executionStateChanged.Event.ReturnData), err)
					}
					return cciptestinterfaces.ExecutionStateChangedEvent{
						SourceChainSelector: protocol.ChainSelector(sourceChainSelector.Uint64()),
						MessageID:           [32]byte(messageId),
						MessageNumber:       sequenceNumber.Uint64(),
						State:               executionState,
						ReturnData:          returnData,
					}, nil
				}
			}
		}
	}

	return cciptestinterfaces.ExecutionStateChangedEvent{
		SourceChainSelector: 0,
		MessageID:           [32]byte{},
		MessageNumber:       0,
		State:               0,
		ReturnData:          nil,
	}, nil
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
