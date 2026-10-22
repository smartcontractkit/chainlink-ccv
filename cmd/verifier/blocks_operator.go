package verifier

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/big"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/cli/blocks"
	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
)

// blocksOperator runs the ccv blocks commands. It is the only caller of the EVM adapter's operator
// functions. Each call checks the chain's mode and the RPC config before it opens the database.
type blocksOperator struct {
	lggr logger.Logger
	// logPollerOn reports whether the mounted EVM config turns the LogPoller on.
	logPollerOn func() (bool, error)
	// evmInfo is the chain's RPC settings from the mounted EVM config.
	evmInfo func(protocol.ChainSelector) (evm.Info, error)
	// openDB opens the verifier database without migrating it, and returns what closes it.
	openDB func(context.Context) (*sql.DB, func(), error)
}

func newBlocksOperator(lggr logger.Logger, secrets *vsecrets.VerifierSecrets) *blocksOperator {
	return &blocksOperator{
		lggr:        lggr,
		logPollerOn: logPollerOnInMountedConfig,
		evmInfo:     evmInfoFromMountedConfig,
		openDB: func(ctx context.Context) (*sql.DB, func(), error) {
			return openBlocksDB(ctx, lggr, secrets)
		},
	}
}

// openBlocksDB opens and pings the verifier database without running migrations, and is used only by
// the blocks commands: they must not create or change the schema they operate on.
func openBlocksDB(ctx context.Context, lggr logger.Logger, secrets *vsecrets.VerifierSecrets) (*sql.DB, func(), error) {
	dbURL := secrets.DatabaseURL()
	if dbURL == "" {
		return nil, nil, errors.New("a database URL must be set (verifier secrets file [db].url or CL_DATABASE_URL) for ccv blocks commands")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open postgres database: %w", err)
	}
	if err := ccvcommon.EnsureDBConnectionContext(ctx, lggr, db); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("failed to ping postgres database: %w", err)
	}
	return db, func() { _ = db.Close() }, nil
}

func logPollerOnInMountedConfig() (bool, error) {
	cfg, _, err := evmconfig.LoadConfigFile(evmconfig.ResolveConfigPath())
	if err != nil {
		return false, fmt.Errorf("the EVM config is needed (set %s): %w", evmconfig.EVMConfigPathEnv, err)
	}
	return cfg.LogPollerEnabled, nil
}

func evmInfoFromMountedConfig(selector protocol.ChainSelector) (evm.Info, error) {
	path := evmconfig.ResolveConfigPath()
	cfg, _, err := evmconfig.LoadConfigFile(path)
	if err != nil {
		return evm.Info{}, fmt.Errorf("chain selector %d: the EVM config is needed for its RPC (set %s): %w", selector, evmconfig.EVMConfigPathEnv, err)
	}
	infos, err := cfg.ToInfos()
	if err != nil {
		return evm.Info{}, fmt.Errorf("chain selector %d: invalid EVM config %s: %w", selector, path, err)
	}
	info, ok := infos[selector.String()]
	if !ok {
		return evm.Info{}, fmt.Errorf("chain selector %d is not configured in the EVM config %s (set %s)", selector, path, evmconfig.EVMConfigPathEnv)
	}
	return info, nil
}

// check fails unless the chain reads through the LogPoller, which is when it has LogPoller data, and
// returns the chain's selector. It reads the EVM config and does no I/O beyond that.
// operation is the node's name for what is being run, which its flag-off error uses.
func (o *blocksOperator) check(evmChainID int64, operation string) (protocol.ChainSelector, error) {
	on, err := o.logPollerOn()
	if err != nil {
		return 0, fmt.Errorf("EVM chain ID %d: cannot tell whether the LogPoller is on: %w", evmChainID, err)
	}
	if !on {
		return 0, fmt.Errorf("EVM chain ID %d reads through the RPC source reader: %s is only available if LogPoller is enabled (set log_poller_enabled in the EVM config from %s)",
			evmChainID, operation, evmconfig.EVMConfigPathEnv)
	}
	return evm.SelectorFromChainID(evmChainID)
}

// open opens the database and checks that it has the LogPoller schema.
func (o *blocksOperator) open(ctx context.Context, evmChainID int64) (*sql.DB, func(), error) {
	db, closeDB, err := o.openDB(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("EVM chain ID %d: %w", evmChainID, err)
	}
	if err := evm.CheckLogPollerSchema(ctx, db); err != nil {
		closeDB()
		return nil, nil, fmt.Errorf("EVM chain ID %d: %w", evmChainID, err)
	}
	return db, closeDB, nil
}

func (o *blocksOperator) FindLCA(ctx context.Context, evmChainID int64) (blocks.LCA, error) {
	selector, err := o.check(evmChainID, "FindLCA")
	if err != nil {
		return blocks.LCA{}, err
	}
	info, err := o.evmInfo(selector)
	if err != nil {
		return blocks.LCA{}, err
	}
	db, closeDB, err := o.open(ctx, evmChainID)
	if err != nil {
		return blocks.LCA{}, err
	}
	defer closeDB()

	lca, err := evm.FindLCA(ctx, db, info, o.lggr)
	if err != nil {
		return blocks.LCA{}, err
	}
	return blocks.LCA{ChainID: lca.ChainID, BlockHash: lca.BlockHash, BlockNumber: lca.BlockNumber}, nil
}

func (o *blocksOperator) RemoveFrom(ctx context.Context, evmChainID, start int64) error {
	if _, err := o.check(evmChainID, "DeleteLogPollerDataAfter"); err != nil {
		return err
	}
	db, closeDB, err := o.open(ctx, evmChainID)
	if err != nil {
		return err
	}
	defer closeDB()

	return evm.RemoveBlocksFrom(ctx, db, o.lggr, big.NewInt(evmChainID), start)
}

// unsupportedBlocksOperator is the ccv blocks commands of a binary that has no LogPoller, so they
// exist for --help and the same runbook but fail with the reason.
type unsupportedBlocksOperator struct{ reason string }

func (u unsupportedBlocksOperator) err() error {
	return fmt.Errorf("ccv blocks is not available: %s", u.reason)
}

func (u unsupportedBlocksOperator) FindLCA(context.Context, int64) (blocks.LCA, error) {
	return blocks.LCA{}, u.err()
}

func (u unsupportedBlocksOperator) RemoveFrom(context.Context, int64, int64) error {
	return u.err()
}
