package evm

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"

	chainselectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	clevmconfig "github.com/smartcontractkit/chainlink-evm/pkg/config"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"

	evmdb "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/db"
)

// logPollerRuntime is the optional capability of a chain runtime that can host a LogPoller. It is
// separate from chainRuntime so runtimes that never read logs, the executor's among them, are unaffected.
type logPollerRuntime interface {
	// LogPoller returns the chain's LogPoller, building and starting it on the first call.
	LogPoller(ctx context.Context, db *sql.DB) (logpoller.LogPoller, error)
	// EVMChainID is the chain's EVM chain ID, which scopes its rows in the LogPoller tables.
	EVMChainID() *big.Int
}

// logPollerInputs is everything a LogPoller is built from. Building it does no network or database I/O.
type logPollerInputs struct {
	chainID     *big.Int
	logger      logger.Logger
	client      logpoller.Client
	headTracker logpoller.HeadTracker
	config      clevmconfig.EVM
	db          *sql.DB
}

type logPollerBuilder func(input logPollerInputs) (logpoller.LogPoller, error)

// buildLogPoller mirrors chainlink-evm's legacyevm chain: Beholder metrics, observed ORM, LogPoller.
// The ORM wraps the verifier's shared pool, which this code must never close.
func buildLogPoller(input logPollerInputs) (logpoller.LogPoller, error) {
	opts, err := standaloneLogPollerOpts(input)
	if err != nil {
		return nil, err
	}
	orm, err := logpoller.NewObservedORM(input.chainID, evmdb.NewLogPollerDB(input.db), input.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create logpoller observed ORM: %w", err)
	}
	return logpoller.NewLogPoller(orm, input.client, input.logger, input.headTracker, opts), nil
}

// standaloneLogPollerOpts are buildLogPoller's options with Beholder metrics: the standalone process
// serves no Prometheus endpoint, so these metrics are its only stall signal.
func standaloneLogPollerOpts(input logPollerInputs) (logpoller.Opts, error) {
	metrics, err := logpoller.NewPromBeholderMetrics(input.chainID.String(), chainselectors.FamilyEVM)
	if err != nil {
		return logpoller.Opts{}, fmt.Errorf("failed to create log poller metrics: %w", err)
	}
	return logPollerOpts(input.config, metrics), nil
}

// logPollerOpts copies legacyevm.NewChain's LogPoller options so the standalone poller behaves as the node's.
func logPollerOpts(cfg clevmconfig.EVM, metrics logpoller.Metrics) logpoller.Opts {
	return logpoller.Opts{
		PollPeriod:               cfg.LogPollInterval(),
		UseFinalityTag:           cfg.FinalityTagEnabled(),
		FinalityDepth:            int64(cfg.FinalityDepth()),
		BackfillBatchSize:        int64(cfg.LogBackfillBatchSize()),
		RPCBatchSize:             int64(cfg.RPCDefaultBatchSize()),
		KeepFinalizedBlocksDepth: int64(cfg.LogKeepBlocksDepth()),
		LogPrunePageSize:         int64(cfg.LogPrunePageSize()),
		BackupPollerBlockDelay:   int64(cfg.BackupLogPollerBlockDelay()), // #nosec G115 -- a block count, as in the node
		ClientErrors:             cfg.NodePool().Errors(),
		SkipEmptyBlocks:          cfg.LogPollerSkipEmptyBlocks(),
		Metrics:                  metrics,
	}
}
