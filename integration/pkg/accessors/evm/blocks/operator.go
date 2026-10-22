package blocks

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"os"

	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// Command is the ccv blocks command, for a binary whose EVM chains can read through the LogPoller.
// Building it does no I/O, so --help works without the EVM config or database.
func Command(lggr logger.Logger) cli.Command {
	op := newBlocksOperator(lggr)
	return cli.Command{
		Name:  "blocks",
		Usage: "Find the last common ancestor and remove stale LogPoller blocks (the node's find-lca and remove-blocks)",
		Subcommands: InitBlocksCommandsWithFactory(func() Deps {
			return Deps{Logger: lggr, Operator: op, Stdout: os.Stdout}
		}),
	}
}

// blocksOperator runs the ccv blocks commands. It is the only caller of the EVM adapter's operator
// functions. Each call checks the chain's mode and the RPC config before it opens the database.
type blocksOperator struct {
	lggr logger.Logger
	// logPollerOn reports whether the mounted EVM config turns the LogPoller on.
	logPollerOn func() (bool, error)
	// evmInfo is the chain's RPC settings from the mounted EVM config.
	evmInfo func(protocol.ChainSelector) (evm.Info, error)
	// openDB opens the EVM database and returns what closes it.
	openDB func(context.Context) (*sql.DB, func(), error)
}

func newBlocksOperator(lggr logger.Logger) *blocksOperator {
	return &blocksOperator{
		lggr:        lggr,
		logPollerOn: logPollerOnInMountedConfig,
		evmInfo:     evmInfoFromMountedConfig,
		openDB: func(ctx context.Context) (*sql.DB, func(), error) {
			return openEVMDB(ctx, lggr)
		},
	}
}

// openEVMDB opens the EVM database named in the mounted EVM secrets file.
func openEVMDB(ctx context.Context, lggr logger.Logger) (*sql.DB, func(), error) {
	secrets, err := evmconfig.LoadSecretsFile(evmconfig.ResolveSecretsPath())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load the EVM secrets (set %s): %w", evmconfig.EVMSecretsPathEnv, err)
	}
	if secrets.DB == nil {
		return nil, nil, fmt.Errorf("ccv blocks commands need the EVM database: set [db].url in the EVM secrets file (%s)", evmconfig.EVMSecretsPathEnv)
	}
	db, err := evm.OpenDB(ctx, lggr, secrets.DB)
	if err != nil {
		return nil, nil, err
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

func (o *blocksOperator) FindLCA(ctx context.Context, evmChainID int64) (LCA, error) {
	selector, err := o.check(evmChainID, "FindLCA")
	if err != nil {
		return LCA{}, err
	}
	info, err := o.evmInfo(selector)
	if err != nil {
		return LCA{}, err
	}
	db, closeDB, err := o.open(ctx, evmChainID)
	if err != nil {
		return LCA{}, err
	}
	defer closeDB()

	lca, err := evm.FindLCA(ctx, db, info, o.lggr)
	if err != nil {
		return LCA{}, err
	}
	return LCA{ChainID: lca.ChainID, BlockHash: lca.BlockHash, BlockNumber: lca.BlockNumber}, nil
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
