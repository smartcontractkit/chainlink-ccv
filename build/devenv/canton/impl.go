package canton

import (
	"context"
	"fmt"
	"math/big"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/noders-team/go-daml/pkg/client"
	"github.com/noders-team/go-daml/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-canton/bindings/ccip/ccvs"
	"github.com/smartcontractkit/chainlink-canton/bindings/ccip/common"
	"github.com/smartcontractkit/chainlink-canton/contracts"
	cantonChangesets "github.com/smartcontractkit/chainlink-canton/deployment/changesets"
	"github.com/smartcontractkit/chainlink-canton/deployment/sequences"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
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

// TODO: this is just for the mocked out addresses, not a real restriction on Canton.
const addressLen = 32

// leftPadBytesWithChar pads the input bytes on the left with the specified character
// to reach the desired length. If data is already >= length, it truncates to length.
func leftPadBytesWithChar(data []byte, length int, padChar byte) []byte {
	if len(data) >= length {
		return data[:length]
	}
	result := make([]byte, length)
	padLen := length - len(data)
	for i := range padLen {
		result[i] = padChar
	}
	copy(result[padLen:], data)
	return result
}

// cantonAddress creates a Canton mock address by padding with 'c' characters.
func cantonAddress(name string) []byte {
	// pad with 'c' because the canton server disallows 'null characters'
	// in a string (i.e. 0 bytes).
	return leftPadBytesWithChar([]byte(name), addressLen, 'c')
}

var (
	_ cciptestinterfaces.CCIP17              = &Chain{}
	_ cciptestinterfaces.CCIP17Configuration = &Chain{}
)

type Chain struct {
	logger zerolog.Logger
	helper *Helper
}

func New(logger zerolog.Logger) *Chain {
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

// ConnectContractsWithSelectors implements cciptestinterfaces.CCIP17Configuration.
func (c *Chain) ConnectContractsWithSelectors(ctx context.Context, e *deployment.Environment, selector uint64, remoteSelectors []uint64, committees *deployments.EnvironmentTopology) error {
	return nil // TODO: implement
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
			// TODO: implement fetching from JD
			addr, ok := nop.SignerAddressByFamily[chainsel.FamilyCanton]
			if !ok || addr == "" {
				return nil, fmt.Errorf("signer address for NOP alias %q family %q not found for committee %q chain %d", nopAlias, chainsel.FamilyCanton, qualifier, selector)
			}

			signers = append(signers, types.TEXT(addr))
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
			Address:       contracts.MustNewInstanceID("dst-token-pool-"+strconv.Itoa(i), user.PrimaryParty).InstanceAddress().Hex(),
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
		Address:       contracts.MustNewInstanceID("executor-1", user.PrimaryParty).InstanceAddress().Hex(),
		Type:          datastore.ContractType(executor.ContractType),
		Version:       executor.Version,
		Qualifier:     devenvcommon.DefaultExecutorQualifier,
		ChainSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add executor address ref: %w", err)
	}
	err = runningDS.AddressRefStore.Add(datastore.AddressRef{
		Address:       contracts.MustNewInstanceID("executor-proxy-1", user.PrimaryParty).InstanceAddress().Hex(),
		Type:          datastore.ContractType(executor.ProxyType),
		Version:       executor.Version,
		Qualifier:     devenvcommon.DefaultExecutorQualifier,
		ChainSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add executor proxy address ref: %w", err)
	}
	// Add rmn remote refs
	err = runningDS.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(cantonAddress("canton rmn remote")),
		Type:          datastore.ContractType(rmn_remote.ContractType),
		Version:       rmn_remote.Version,
		ChainSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add rmn remote address ref: %w", err)
	}

	return runningDS.Seal(), nil
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
	h, err := NewHelperFromBlockchainInput(grpcURL, jwt)
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
	return cciptestinterfaces.ExecutionStateChangedEvent{}, nil // TODO: implement
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
