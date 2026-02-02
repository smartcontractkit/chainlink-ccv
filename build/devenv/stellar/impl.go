package stellar

import (
	"context"
	"fmt"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/stellar/go-stellar-sdk/clients/rpcclient"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	offrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/offramp"
	onrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/onramp"
	routeroperations "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
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

// TODO: make sure its included in chain-selectors repo
const FamilyStellar = "stellar"
const stellarAddressLen = 32

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

// stellarAddress creates a Stellar mock address from a name
// TODO: addresses in Stellar are based on the Network ID and its sha-256 hash (over the Network passphrase).
func stellarAddress(name string) []byte {
	// pad with 's' for stellar to create unique mock addresses
	return leftPadBytesWithChar([]byte(name), stellarAddressLen, 's')
}

var (
	_ cciptestinterfaces.CCIP17              = &Chain{}
	_ cciptestinterfaces.CCIP17Configuration = &Chain{}
)

// Chain implements the CCIP17 and CCIP17Configuration interfaces for Stellar/Soroban.
type Chain struct {
	logger            zerolog.Logger
	rpcClient         *rpcclient.Client
	networkPassphrase string
}

// New creates a new Stellar Chain instance.
func New(logger zerolog.Logger) *Chain {
	return &Chain{
		logger: logger,
	}
}

// ChainFamily implements cciptestinterfaces.CCIP17Configuration.
func (c *Chain) ChainFamily() string {
	return FamilyStellar
}

// ConfigureNodes implements cciptestinterfaces.CCIP17Configuration.
// Returns TOML configuration for Chainlink nodes to connect to Stellar.
func (c *Chain) ConfigureNodes(ctx context.Context, blockchain *blockchain.Input) (string, error) {
	// TODO: implement Stellar-specific node configuration
	// This should return TOML config for:
	// - Soroban RPC endpoint
	// - Network passphrase
	// - Any Stellar-specific settings
	return "", nil
}

// ConnectContractsWithSelectors implements cciptestinterfaces.CCIP17Configuration.
// Connects this chain's OnRamp to OffRamps on remote chains and configures CommitteeVerifiers.
func (c *Chain) ConnectContractsWithSelectors(ctx context.Context, e *deployment.Environment, selector uint64, remoteSelectors []uint64, committees *deployments.EnvironmentTopology) error {
	// TODO: implement contract connection logic for Stellar
	// This should:
	// 1. Configure the OnRamp with destination chain selectors
	// 2. Configure the OffRamp with source chain selectors
	// 3. Set up CommitteeVerifier signers from the topology
	return nil
}

// DeployContractsForSelector implements cciptestinterfaces.CCIP17Configuration.
// Deploys CCIP contracts for the given chain selector.
func (c *Chain) DeployContractsForSelector(ctx context.Context, env *deployment.Environment, selector uint64, committees *deployments.EnvironmentTopology) (datastore.DataStore, error) {
	c.logger.Info().Uint64("selector", selector).Msg("Deploying Stellar CCIP contracts (mocked)")

	// TODO: Deploy actual Soroban contracts from chainlink-stellar, mock for now

	// Mock a Stellar deployment
	ds := datastore.NewMemoryDataStore()

	// Add OnRamp
	ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(stellarAddress("stellar onramp")),
		ChainSelector: selector,
		Type:          datastore.ContractType(onrampoperations.ContractType),
		Version:       semver.MustParse(onrampoperations.Deploy.Version()),
	})

	// Add OffRamp
	ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(stellarAddress("stellar offramp")),
		ChainSelector: selector,
		Type:          datastore.ContractType(offrampoperations.ContractType),
		Version:       semver.MustParse(offrampoperations.Deploy.Version()),
	})

	// Add Router
	ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(stellarAddress("stellar router")),
		ChainSelector: selector,
		Type:          datastore.ContractType(routeroperations.ContractType),
		Version:       semver.MustParse(routeroperations.Deploy.Version()),
	})

	// Add token pools
	for i, combo := range devenvcommon.AllTokenCombinations() {
		addressRef := combo.DestPoolAddressRef()
		ds.AddressRefStore.Add(datastore.AddressRef{
			Address:       hexutil.Encode(stellarAddress(fmt.Sprintf("stellar dst token %d", i))),
			Type:          addressRef.Type,
			Version:       addressRef.Version,
			Qualifier:     addressRef.Qualifier,
			ChainSelector: selector,
		})
		addressRef = combo.SourcePoolAddressRef()
		ds.AddressRefStore.Add(datastore.AddressRef{
			Address:       hexutil.Encode(stellarAddress(fmt.Sprintf("stellar src token %d", i))),
			Type:          addressRef.Type,
			Version:       addressRef.Version,
			Qualifier:     addressRef.Qualifier,
			ChainSelector: selector,
		})
	}

	// Add CCTP refs (keeping it here as a reference, will uncomment later)
	// ds.AddressRefStore.Add(datastore.AddressRef{
	// 	Address:       hexutil.Encode(stellarAddress("stellar cctp mtp")),
	// 	Type:          datastore.ContractType(cctp_message_transmitter_proxy.ContractType),
	// 	Version:       semver.MustParse(cctp_message_transmitter_proxy.Deploy.Version()),
	// 	Qualifier:     devenvcommon.CCTPContractsQualifier,
	// 	ChainSelector: selector,
	// })
	// ds.AddressRefStore.Add(datastore.AddressRef{
	// 	Address:       hexutil.Encode(stellarAddress("stellar cctp rslvr")),
	// 	Type:          datastore.ContractType(cctp_verifier.ResolverType),
	// 	Version:       semver.MustParse(cctp_verifier.Deploy.Version()),
	// 	Qualifier:     devenvcommon.CCTPContractsQualifier,
	// 	ChainSelector: selector,
	// })
	// ds.AddressRefStore.Add(datastore.AddressRef{
	// 	Address:       hexutil.Encode(stellarAddress("stellar cctp vrfr")),
	// 	Type:          datastore.ContractType(cctp_verifier.ContractType),
	// 	Version:       semver.MustParse(cctp_verifier.Deploy.Version()),
	// 	Qualifier:     devenvcommon.CCTPContractsQualifier,
	// 	ChainSelector: selector,
	// })
	// ds.AddressRefStore.Add(datastore.AddressRef{
	// 	Address:       hexutil.Encode(stellarAddress("stellar usdc token")),
	// 	Type:          datastore.ContractType(burnminterc677ops.ContractType),
	// 	Version:       burnminterc677ops.Version,
	// 	Qualifier:     devenvcommon.CCTPContractsQualifier,
	// 	ChainSelector: selector,
	// })
	// ds.AddressRefStore.Add(datastore.AddressRef{
	// 	Address:       hexutil.Encode(stellarAddress("usdc token pool prx")),
	// 	Type:          datastore.ContractType(usdc_token_pool_proxy.ContractType),
	// 	Version:       semver.MustParse(usdc_token_pool_proxy.Deploy.Version()),
	// 	Qualifier:     devenvcommon.CCTPContractsQualifier,
	// 	ChainSelector: selector,
	// })

	// Add CCV refs
	for i, qualifier := range []string{
		devenvcommon.DefaultCommitteeVerifierQualifier,
		devenvcommon.SecondaryCommitteeVerifierQualifier,
		devenvcommon.TertiaryCommitteeVerifierQualifier,
		devenvcommon.QuaternaryReceiverQualifier,
	} {
		ds.AddressRefStore.Add(datastore.AddressRef{
			Address:       hexutil.Encode(stellarAddress(fmt.Sprintf("stellar ccv %d", i))),
			Type:          datastore.ContractType(committee_verifier.ResolverType),
			Version:       semver.MustParse(committee_verifier.Deploy.Version()),
			Qualifier:     qualifier,
			ChainSelector: selector,
		})
	}

	// Add executor refs
	ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(stellarAddress("stellar exec")),
		Type:          datastore.ContractType(executor.ContractType),
		Version:       semver.MustParse(executor.Deploy.Version()),
		Qualifier:     devenvcommon.DefaultExecutorQualifier,
		ChainSelector: selector,
	})
	ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(stellarAddress("stellar exec prx")),
		Type:          datastore.ContractType(executor.ProxyType),
		Version:       semver.MustParse(executor.DeployProxy.Version()),
		Qualifier:     devenvcommon.DefaultExecutorQualifier,
		ChainSelector: selector,
	})

	// Add RMN remote refs
	ds.AddressRefStore.Add(datastore.AddressRef{
		Address:       hexutil.Encode(stellarAddress("stellar rmn remote")),
		Type:          datastore.ContractType(rmn_remote.ContractType),
		Version:       semver.MustParse(rmn_remote.Deploy.Version()),
		ChainSelector: selector,
	})

	return ds.Seal(), nil
}

// DeployLocalNetwork implements cciptestinterfaces.CCIP17Configuration.
// Deploys a local Stellar network for testing.
func (c *Chain) DeployLocalNetwork(ctx context.Context, input *blockchain.Input) (*blockchain.Output, error) {
	c.logger.Info().Msg("Deploying Stellar local network")

	// TODO: Start a local Stellar quickstart container or standalone node
	// The blockchain.Input should contain Stellar-specific configuration like:
	// - Network passphrase
	// - Soroban RPC URL/port

	// TODO: add stellar specific configuration to the input and to CTF

	out, err := blockchain.NewBlockchainNetwork(input)
	if err != nil {
		return nil, fmt.Errorf("failed to create Stellar blockchain network: %w", err)
	}

	// TODO: Initialize the Stellar RPC client with the network endpoints
	// sorobanRPCURL := ...
	// networkPassphrase := ...
	//
	// c.rpcClient = rpcclient.NewClient(sorobanRPCURL, &http.Client{Timeout: 30 * time.Second})
	// c.networkPassphrase = networkPassphrase

	return out, nil
}

// FundAddresses implements cciptestinterfaces.CCIP17Configuration.
// Funds addresses with native Stellar Lumens (XLM).
func (c *Chain) FundAddresses(ctx context.Context, bc *blockchain.Input, addresses []protocol.UnknownAddress, nativeAmount *big.Int) error {
	// TODO: implement XLM funding for addresses
	// Use the Stellar friendbot for testnet or direct transfers for local networks
	// https://lab.stellar.org/account/fund?$=network$id=testnet&label=Testnet&horizonUrl=https:////horizon-testnet.stellar.org&rpcUrl=https:////soroban-testnet.stellar.org&passphrase=Test%20SDF%20Network%20/;%20September%202015;;
	c.logger.Info().
		Int("numAddresses", len(addresses)).
		Str("amount", nativeAmount.String()).
		Msg("Funding Stellar addresses (not implemented)")
	return nil
}

// FundNodes implements cciptestinterfaces.CCIP17Configuration.
// Funds Chainlink nodes with XLM and LINK tokens.
func (c *Chain) FundNodes(ctx context.Context, cls []*simple_node_set.Input, bc *blockchain.Input, linkAmount, nativeAmount *big.Int) error {
	// TODO: implement node funding for Stellar
	// This should:
	// 1. Fund each node's Stellar address with XLM
	// 2. Fund each node with LINK tokens (if LINK is available on Stellar)
	c.logger.Info().
		Int("numNodes", len(cls)).
		Str("linkAmount", linkAmount.String()).
		Str("nativeAmount", nativeAmount.String()).
		Msg("Funding Stellar nodes (not implemented)")
	return nil
}

// Curse implements cciptestinterfaces.CCIP17.
// Curses a list of chains on this chain's RMN.
func (c *Chain) Curse(ctx context.Context, subjects [][16]byte) error {
	// TODO: implement RMN curse for Stellar
	return nil
}

// ExposeMetrics implements cciptestinterfaces.CCIP17.
// Exposes Prometheus metrics for monitoring.
func (c *Chain) ExposeMetrics(ctx context.Context, source, dest uint64) ([]string, *prometheus.Registry, error) {
	// TODO: implement metrics exposure for Stellar lanes
	return nil, nil, nil
}

// GetEOAReceiverAddress implements cciptestinterfaces.CCIP17.
// Gets an EOA receiver address for this chain.
func (c *Chain) GetEOAReceiverAddress() (protocol.UnknownAddress, error) {
	// TODO: implement - return a Stellar account address that can receive messages
	return protocol.UnknownAddress{}, nil
}

// GetExpectedNextSequenceNumber implements cciptestinterfaces.CCIP17.
// Gets the expected next sequence number for messages to the specified destination.
func (c *Chain) GetExpectedNextSequenceNumber(ctx context.Context, to uint64) (uint64, error) {
	// TODO: implement - query the OnRamp contract for the next sequence number
	return 0, nil
}

// GetMaxDataBytes implements cciptestinterfaces.CCIP17.
// Gets the maximum data size for a CCIP message to the specified remote chain.
func (c *Chain) GetMaxDataBytes(ctx context.Context, remoteChainSelector uint64) (uint32, error) {
	// TODO: implement - query the OnRamp contract for max data bytes
	return 0, nil
}

// GetRoundRobinUser implements cciptestinterfaces.CCIP17.
// Gets a round-robin user for sending transactions.
func (c *Chain) GetRoundRobinUser() func() *bind.TransactOpts {
	// NOTE: bind.TransactOpts is EVM-specific. For Stellar, we would need a different
	// transaction signing mechanism. This method may need to be refactored for
	// chain-agnostic transaction signing.
	return nil
}

// GetSenderAddress implements cciptestinterfaces.CCIP17.
// Gets the sender address for this chain.
func (c *Chain) GetSenderAddress() (protocol.UnknownAddress, error) {
	// TODO: implement - return the default sender's Stellar address
	return protocol.UnknownAddress{}, nil
}

// GetTokenBalance implements cciptestinterfaces.CCIP17.
// Gets the balance of a token for an address.
func (c *Chain) GetTokenBalance(ctx context.Context, address, tokenAddress protocol.UnknownAddress) (*big.Int, error) {
	// TODO: implement - query the token balance using Soroban RPC
	return nil, nil
}

// GetUserNonce implements cciptestinterfaces.CCIP17.
// Returns the nonce for the given user address on this chain.
func (c *Chain) GetUserNonce(ctx context.Context, userAddress protocol.UnknownAddress) (uint64, error) {
	// TODO: implement - query the user's sequence number from the Stellar network
	return 0, nil
}

// ManuallyExecuteMessage implements cciptestinterfaces.CCIP17.
// Manually executes a CCIP message on this chain.
func (c *Chain) ManuallyExecuteMessage(ctx context.Context, message protocol.Message, gasLimit uint64, ccvs []protocol.UnknownAddress, verifierResults [][]byte) (cciptestinterfaces.ExecutionStateChangedEvent, error) {
	// TODO: implement - call the OffRamp contract to execute a message manually
	return cciptestinterfaces.ExecutionStateChangedEvent{}, nil
}

// SendMessage implements cciptestinterfaces.CCIP17.
// Sends a CCIP message to the specified destination chain.
func (c *Chain) SendMessage(ctx context.Context, dest uint64, fields cciptestinterfaces.MessageFields, opts cciptestinterfaces.MessageOptions) (cciptestinterfaces.MessageSentEvent, error) {
	// TODO: implement - call the Router/OnRamp contract to send a message
	c.logger.Info().
		Uint64("destChainSelector", dest).
		Str("receiver", fields.Receiver.String()).
		Msg("Sending CCIP message from Stellar (not implemented)")
	return cciptestinterfaces.MessageSentEvent{}, nil
}

// SendMessageWithNonce implements cciptestinterfaces.CCIP17.
// Sends a CCIP message with a specific nonce.
func (c *Chain) SendMessageWithNonce(ctx context.Context, dest uint64, fields cciptestinterfaces.MessageFields, opts cciptestinterfaces.MessageOptions, sender *bind.TransactOpts, nonce *atomic.Uint64, disableTokenAmountCheck bool) (cciptestinterfaces.MessageSentEvent, error) {
	// TODO: implement - call the Router/OnRamp contract with specific nonce
	// NOTE: sender *bind.TransactOpts is EVM-specific and will need adaptation for Stellar
	return cciptestinterfaces.MessageSentEvent{}, nil
}

// Uncurse implements cciptestinterfaces.CCIP17.
// Uncurses a list of chains on this chain's RMN.
func (c *Chain) Uncurse(ctx context.Context, subjects [][16]byte) error {
	// TODO: implement RMN uncurse for Stellar
	return nil
}

// WaitOneExecEventBySeqNo implements cciptestinterfaces.CCIP17.
// Waits for exactly one execution state change event.
func (c *Chain) WaitOneExecEventBySeqNo(ctx context.Context, from, seq uint64, timeout time.Duration) (cciptestinterfaces.ExecutionStateChangedEvent, error) {
	// TODO: implement - poll for execution events from the OffRamp contract
	return cciptestinterfaces.ExecutionStateChangedEvent{}, nil
}

// WaitOneSentEventBySeqNo implements cciptestinterfaces.CCIP17.
// Waits for exactly one message sent event.
func (c *Chain) WaitOneSentEventBySeqNo(ctx context.Context, to, seq uint64, timeout time.Duration) (cciptestinterfaces.MessageSentEvent, error) {
	// TODO: implement - poll for sent events from the OnRamp contract
	return cciptestinterfaces.MessageSentEvent{}, nil
}

// GetChainDetailsBySelectorAndFamily is a helper to get chain details for Stellar.
// This wraps the chain-selectors call with Stellar family support.
func GetChainDetailsBySelectorAndFamily(chainID string) (chainsel.ChainDetails, error) {
	// TODO: Once Stellar is added to chain-selectors, use:
	// return chainsel.GetChainDetailsByChainIDAndFamily(chainID, FamilyStellar)
	//
	// For now, return a placeholder
	return chainsel.ChainDetails{}, fmt.Errorf("Stellar chain selector lookup not yet implemented for chainID: %s", chainID)
}
