package canton

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/noders-team/go-daml/pkg/client"

	"github.com/smartcontractkit/chainlink-canton-internal/bindings/compile"
	"github.com/smartcontractkit/chainlink-canton-internal/contracts"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/canton"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

type CCIP17Canton struct {
	e            *deployment.Environment
	ds           datastore.DataStore
	chain        canton.Chain
	logger       zerolog.Logger
	chainDetails chainsel.ChainDetails
}

func NewEmptyCCIP17Canton() *CCIP17Canton {
	return &CCIP17Canton{
		logger: log.
			Output(zerolog.ConsoleWriter{Out: os.Stderr}).
			Level(zerolog.DebugLevel).
			With().
			Fields(map[string]any{"component": "CCIP17Canton"}).
			Logger(),
	}
}

func (c CCIP17Canton) Family() string {
	return chainsel.FamilyCanton
}

func (c CCIP17Canton) GetEOAReceiverAddress() (protocol.UnknownAddress, error) {
	// TODO implement me
	panic("implement me")
}

func (c CCIP17Canton) GetSenderAddress() (protocol.UnknownAddress, error) {
	// TODO implement me
	panic("implement me")
}

func (c CCIP17Canton) SendMessage(ctx context.Context, dest uint64, fields cciptestinterfaces.MessageFields, opts cciptestinterfaces.MessageOptions) (cciptestinterfaces.MessageSentEvent, error) {
	// TODO implement me
	panic("implement me")
}

func (c CCIP17Canton) SendMessageWithNonce(ctx context.Context, dest uint64, fields cciptestinterfaces.MessageFields, opts cciptestinterfaces.MessageOptions, nonce *atomic.Uint64, disableTokenAmountCheck bool) (cciptestinterfaces.MessageSentEvent, error) {
	// TODO implement me
	panic("implement me")
}

func (c CCIP17Canton) GetUserNonce(ctx context.Context) (uint64, error) {
	// TODO implement me
	panic("implement me")
}

func (c CCIP17Canton) GetExpectedNextSequenceNumber(ctx context.Context, to uint64) (uint64, error) {
	// TODO implement me
	panic("implement me")
}

func (c CCIP17Canton) WaitOneSentEventBySeqNo(ctx context.Context, to, seq uint64, timeout time.Duration) (cciptestinterfaces.MessageSentEvent, error) {
	// TODO implement me
	panic("implement me")
}

func (c CCIP17Canton) WaitOneExecEventBySeqNo(ctx context.Context, from, seq uint64, timeout time.Duration) (cciptestinterfaces.ExecutionStateChangedEvent, error) {
	// TODO implement me
	panic("implement me")
}

func (c CCIP17Canton) GetTokenBalance(ctx context.Context, address, tokenAddress protocol.UnknownAddress) (*big.Int, error) {
	// TODO implement me
	panic("implement me")
}

func (c CCIP17Canton) GetMaxDataBytes(ctx context.Context, remoteChainSelector uint64) (uint32, error) {
	// TODO implement me
	panic("implement me")
}

func (c CCIP17Canton) ManuallyExecuteMessage(ctx context.Context, message protocol.Message, gasLimit uint64, ccvs []protocol.UnknownAddress, verifierResults [][]byte) (cciptestinterfaces.ExecutionStateChangedEvent, error) {
	// TODO implement me
	panic("implement me")
}

func (c CCIP17Canton) Curse(ctx context.Context, subjects [][16]byte) error {
	// TODO implement me
	panic("implement me")
}

func (c CCIP17Canton) Uncurse(ctx context.Context, subjects [][16]byte) error {
	// TODO implement me
	panic("implement me")
}

func (c CCIP17Canton) ExposeMetrics(ctx context.Context, source, dest uint64) ([]string, *prometheus.Registry, error) {
	// TODO implement me
	panic("implement me")
}

func (c CCIP17Canton) ChainFamily() string {
	return chainsel.FamilyCanton
}

func (c CCIP17Canton) DeployContractsForSelector(ctx context.Context, env *deployment.Environment, selector uint64, committees []cciptestinterfaces.OnChainCommittees) (datastore.DataStore, error) {
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
	coinDar, err := compile.Package(contracts.Coin)
	if err != nil {
		return nil, fmt.Errorf("failed to compile Coin contract: %w", err)
	}
	err = c1.PackageMng.UploadDarFile(ctx, coinDar.Dar, uuid.New().String())
	if err != nil {
		return nil, fmt.Errorf("failed to upload Dar file: %w", err)
	}
	l.Info().Msg("Uploaded Coin Dar file")

	// TODO Deploy contracts

	return runningDs.Seal(), nil
}

func (c CCIP17Canton) ConnectContractsWithSelectors(ctx context.Context, e *deployment.Environment, selector uint64, remoteSelectors []uint64, committees []cciptestinterfaces.OnChainCommittees) error {
	// TODO implement me
	panic("implement me")
}

func (c CCIP17Canton) DeployLocalNetwork(ctx context.Context, bc *blockchain.Input) (*blockchain.Output, error) {
	c.logger.Info().Msg("Deploying Canton Network")
	out, err := blockchain.NewBlockchainNetwork(bc)
	if err != nil {
		return nil, fmt.Errorf("failed to deploy Canton Network: %w", err)
	}
	// TODO set ChainID properly
	out.ChainID = bc.ChainID

	return out, nil
}

func (c CCIP17Canton) ConfigureNodes(ctx context.Context, blockchain *blockchain.Input) (string, error) {
	// TODO Return CL Node config for Canton if necessary
	return "", nil
}

func (c CCIP17Canton) FundNodes(ctx context.Context, cls []*simple_node_set.Input, bc *blockchain.Input, linkAmount, nativeAmount *big.Int) error {
	// Not required for Canton
	return nil
}

func (c CCIP17Canton) FundAddresses(ctx context.Context, bc *blockchain.Input, addresses []protocol.UnknownAddress, nativeAmount *big.Int) error {
	// TODO implement me
	panic("implement me")
}
