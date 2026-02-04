package canton

import (
	"context"
	"fmt"
	"math/big"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/cctp_message_transmitter_proxy"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/cctp_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	offrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/offramp"
	onrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/onramp"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/usdc_token_pool_proxy"
	routeroperations "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	burnminterc677ops "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/burn_mint_erc20_with_drip"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
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
func (c *Chain) DeployContractsForSelector(ctx context.Context, env *deployment.Environment, selector uint64, committees *deployments.EnvironmentTopology) (datastore.DataStore, error) {
	// Deploy the json-tests DAR so that its available on the network.
	// NOTE: this is hacky, but temporary, until we deploy the real CCIP contracts.
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	darPath := filepath.Join(dir, "../tests/integration/canton/json-tests-0.0.1.dar")
	err := c.helper.UploadDar(ctx, darPath)
	if err != nil {
		return nil, fmt.Errorf("failed to upload json-tests DAR: %w", err)
	}

	// Mock out a Canton deployment for now.
	ds := datastore.NewMemoryDataStore()
	// Add Onramp
	err = ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(cantonAddress("canton onramp")),
		ChainSelector: selector,
		Type:          datastore.ContractType(onrampoperations.ContractType),
		Version:       semver.MustParse(onrampoperations.Deploy.Version()),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add canton onramp address ref: %w", err)
	}
	// Add OffRamp
	err = ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(cantonAddress("canton offramp")),
		ChainSelector: selector,
		Type:          datastore.ContractType(offrampoperations.ContractType),
		Version:       semver.MustParse(offrampoperations.Deploy.Version()),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add canton offramp address ref: %w", err)
	}
	// Add Router
	err = ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(cantonAddress("canton router")),
		ChainSelector: selector,
		Type:          datastore.ContractType(routeroperations.ContractType),
		Version:       semver.MustParse(routeroperations.Deploy.Version()),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add canton router address ref: %w", err)
	}
	// Add token pools
	for i, combo := range devenvcommon.AllTokenCombinations() {
		addressRef := combo.DestPoolAddressRef()
		err = ds.AddressRefStore.Add(datastore.AddressRef{
			Address:       hexutil.Encode(cantonAddress(fmt.Sprintf("canton dst token %d", i))),
			Type:          addressRef.Type,
			Version:       addressRef.Version,
			Qualifier:     addressRef.Qualifier,
			ChainSelector: selector,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to add canton dst token %d address ref: %w", i, err)
		}
	}
	// Add CCTP refs
	err = ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(cantonAddress("canton cctp mtp")),
		Type:          datastore.ContractType(cctp_message_transmitter_proxy.ContractType),
		Version:       semver.MustParse(cctp_message_transmitter_proxy.Deploy.Version()),
		Qualifier:     devenvcommon.CCTPContractsQualifier,
		ChainSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add canton cctp mtp address ref: %w", err)
	}
	err = ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(cantonAddress("canton cctp rslvr")),
		Type:          datastore.ContractType(cctp_verifier.ResolverType),
		Version:       semver.MustParse(cctp_verifier.Deploy.Version()),
		Qualifier:     devenvcommon.CCTPContractsQualifier,
		ChainSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add canton cctp rslvr address ref: %w", err)
	}
	err = ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(cantonAddress("canton cctp vrfr")),
		Type:          datastore.ContractType(cctp_verifier.ContractType),
		Version:       semver.MustParse(cctp_verifier.Deploy.Version()),
		Qualifier:     devenvcommon.CCTPContractsQualifier,
		ChainSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add canton cctp vrfr address ref: %w", err)
	}
	err = ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(cantonAddress("canton usdc token")),
		Type:          datastore.ContractType(burnminterc677ops.ContractType),
		Version:       burnminterc677ops.Version,
		Qualifier:     devenvcommon.CCTPContractsQualifier,
		ChainSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add canton usdc token address ref: %w", err)
	}
	err = ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(cantonAddress("usdc token pool prx")),
		Type:          datastore.ContractType(usdc_token_pool_proxy.ContractType),
		Version:       semver.MustParse(usdc_token_pool_proxy.Deploy.Version()),
		Qualifier:     devenvcommon.CCTPContractsQualifier,
		ChainSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add canton usdc token pool prx address ref: %w", err)
	}
	// Add CCV refs
	for i, qualifier := range []string{
		devenvcommon.DefaultCommitteeVerifierQualifier,
		devenvcommon.SecondaryCommitteeVerifierQualifier,
		devenvcommon.TertiaryCommitteeVerifierQualifier,
		devenvcommon.QuaternaryReceiverQualifier,
	} {
		err = ds.AddressRefStore.Add(datastore.AddressRef{
			Address:       hexutil.Encode(cantonAddress(fmt.Sprintf("canton ccv %d", i))),
			Type:          datastore.ContractType(committee_verifier.ResolverType),
			Version:       semver.MustParse(committee_verifier.Deploy.Version()),
			Qualifier:     qualifier,
			ChainSelector: selector,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to add canton ccv %d address ref: %w", i, err)
		}
	}
	// Add executor refs
	err = ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(cantonAddress("canton exec")),
		Type:          datastore.ContractType(executor.ContractType),
		Version:       semver.MustParse(executor.Deploy.Version()),
		Qualifier:     devenvcommon.DefaultExecutorQualifier,
		ChainSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add canton exec address ref: %w", err)
	}
	err = ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(cantonAddress("canton exec prx")),
		Type:          datastore.ContractType(executor.ProxyType),
		Version:       semver.MustParse(executor.DeployProxy.Version()),
		Qualifier:     devenvcommon.DefaultExecutorQualifier,
		ChainSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add canton exec prx address ref: %w", err)
	}
	// Add rmn remote refs
	err = ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(cantonAddress("canton rmn remote")),
		Type:          datastore.ContractType(rmn_remote.ContractType),
		Version:       semver.MustParse(rmn_remote.Deploy.Version()),
		ChainSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add canton rmn remote address ref: %w", err)
	}
	return ds.Seal(), nil
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
