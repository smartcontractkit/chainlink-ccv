package canton

import (
	"context"
	"fmt"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/google/uuid"
	"github.com/noders-team/go-daml/pkg/client"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-canton-internal/contracts"
	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

var (
	_ cciptestinterfaces.CCIP17              = &Chain{}
	_ cciptestinterfaces.CCIP17Configuration = &Chain{}
)

type Chain struct {
	logger zerolog.Logger
}

func New(logger zerolog.Logger) *Chain {
	return &Chain{
		logger: logger,
	}
}

func (c *Chain) Family() string {
	return chainsel.FamilyCanton
}

func (c *Chain) ChainFamily() string {
	return chainsel.FamilyCanton
}

// DeployContractsForSelector implements cciptestinterfaces.CCIP17Configuration.
func (c *Chain) DeployContractsForSelector(ctx context.Context, env *deployment.Environment, selector uint64, committees *deployments.EnvironmentTopology) (datastore.DataStore, error) {
	l := c.logger
	l.Info().Msg("Configuring contracts for selector")
	l.Info().Any("Selector", selector).Msg("Deploying for chain selector")
	cc := env.BlockChains.CantonChains()[selector]
	participant1 := cc.Participants[0]
	jwToken, err := participant1.JWTProvider.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT for participant 1: %w", err)
	}
	c1, err := client.NewDamlClient(jwToken, participant1.Endpoints.GRPCLedgerAPIURL).
		WithAdminAddress(participant1.Endpoints.AdminAPIURL).
		Build(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create client for participant 1: %w", err)
	}
	defer c1.Close()

	runningDs := datastore.NewMemoryDataStore()

	// Deploy contracts

	// Using the Coin dar file as an example
	coinDar, err := contracts.GetDar(contracts.Coin, contracts.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to compile Coin contract: %w", err)
	}
	err = c1.PackageMng.UploadDarFile(ctx, coinDar, uuid.New().String())
	if err != nil {
		return nil, fmt.Errorf("failed to upload Dar file: %w", err)
	}
	l.Info().Msg("Uploaded Coin Dar file")

	// TODO Deploy contracts

	return runningDs.Seal(), nil
}

// ConfigureNodes implements cciptestinterfaces.CCIP17Configuration.
func (c *Chain) ConfigureNodes(ctx context.Context, blockchain *blockchain.Input) (string, error) {
	return "", nil // TODO: implement
}

// ConnectContractsWithSelectors implements cciptestinterfaces.CCIP17Configuration.
func (c *Chain) ConnectContractsWithSelectors(ctx context.Context, e *deployment.Environment, selector uint64, remoteSelectors []uint64, committees *deployments.EnvironmentTopology) error {
	return nil // TODO: implement
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
