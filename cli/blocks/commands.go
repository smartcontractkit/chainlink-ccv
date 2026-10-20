// Package blocks is the standalone verifier's version of the Chainlink node's find-lca and
// remove-blocks commands, which resolve a LogPoller finality violation. It knows nothing of the EVM
// adapter: an Operator does the work, so this package only parses and prints.
package blocks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// LCA is the highest stored block whose hash the chain RPC also has.
type LCA struct {
	ChainID     string
	BlockHash   string
	BlockNumber int64
}

// Operator does the work against the LogPoller's data. Every method fails, changing nothing, when the
// chain does not read through the LogPoller.
type Operator interface {
	// FindLCA only reads, so it is safe with the verifier running.
	FindLCA(ctx context.Context, evmChainID int64) (LCA, error)
	// RemoveFrom deletes the chain's blocks and logs from start up, start included.
	RemoveFrom(ctx context.Context, evmChainID, start int64) error
}

// Deps holds what the commands run on.
type Deps struct {
	Logger   logger.Logger
	Operator Operator
	Stdout   io.Writer
}

// InitBlocksCommandsWithFactory returns the commands, which get their Deps from getDeps when one
// runs. Building Deps connects to the database, so --help must never call it.
func InitBlocksCommandsWithFactory(getDeps func() Deps) []cli.Command {
	return []cli.Command{
		{
			Name: "find-lca",
			Usage: "Find latest common block stored in DB and on chain. " +
				"Only reads: works with the verifier running or stopped.",
			Description: "Takes no verifier ID: the LogPoller tables are scoped by EVM chain ID, not by verifier.",
			Action:      findLCAAction(getDeps),
			Flags:       []cli.Flag{evmChainIDFlag()},
		},
		{
			Name:  "remove-blocks",
			Usage: "Deletes block range and all associated data. The verifier must be stopped.",
			Description: "Deletes evm.log_poller_blocks and evm.logs rows of the chain with block number >= --start, " +
				"--start included. The verifier must be stopped: this does not stop a running LogPoller from " +
				"storing again. Choose one more than the block find-lca prints, so only data that left the chain " +
				"is deleted; deleting data older than the filter retention cannot be re-indexed cheaply. " +
				"Takes no verifier ID: the LogPoller tables are scoped by EVM chain ID, not by verifier.",
			Action: removeBlocksAction(getDeps),
			Flags: []cli.Flag{
				evmChainIDFlag(),
				cli.IntFlag{
					Name:     "start",
					Usage:    "Beginning of block range to be deleted",
					Required: true,
				},
			},
		},
	}
}

func evmChainIDFlag() cli.Flag {
	return cli.Int64Flag{
		Name:     "evm-chain-id",
		Usage:    "Chain ID of the EVM-based blockchain",
		Required: true,
	}
}

func findLCAAction(getDeps func() Deps) func(*cli.Context) error {
	return func(c *cli.Context) error {
		chainID := c.Int64("evm-chain-id")
		deps := getDeps()
		lca, err := deps.Operator.FindLCA(context.Background(), chainID)
		if err != nil {
			deps.Logger.Errorw("find-lca failed", "evm_chain_id", chainID, "error", err)
			return fmt.Errorf("find-lca for EVM chain ID %d failed: %w", chainID, err)
		}
		_, _ = fmt.Fprintln(deps.Stdout, "Last Common Ancestor")
		renderList(deps.Stdout, []string{"ChainID", "Block Hash", "Block Number"}, []string{lca.ChainID, lca.BlockHash, strconv.FormatInt(lca.BlockNumber, 10)})
		return nil
	}
}

func removeBlocksAction(getDeps func() Deps) func(*cli.Context) error {
	return func(c *cli.Context) error {
		chainID := c.Int64("evm-chain-id")
		start := int64(c.Int("start"))
		if start <= 0 {
			return errors.New("must pass a positive value in '--start' parameter")
		}
		deps := getDeps()

		if err := deps.Operator.RemoveFrom(context.Background(), chainID, start); err != nil {
			deps.Logger.Errorw("remove-blocks failed", "evm_chain_id", chainID, "start", start, "error", err)
			return fmt.Errorf("remove-blocks for EVM chain ID %d failed: %w", chainID, err)
		}
		deps.Logger.Infof("RemoveBlocks: successfully removed blocks")
		return nil
	}
}

// renderList prints one item as the node's find-lca does: a label column padded to the longest
// label, between dividers as wide as the longest line.
func renderList(out io.Writer, fields, row []string) {
	var maxLabel int
	for _, field := range fields {
		maxLabel = max(maxLabel, len(field))
	}
	var maxLine int
	lines := make([]string, 0, len(fields))
	for i, field := range fields {
		line := fmt.Sprintf("%v: %v%v", field, strings.Repeat(" ", maxLabel-len(field)), row[i])
		maxLine = max(maxLine, len(line))
		lines = append(lines, line)
	}
	divider := "\n" + strings.Repeat("-", maxLine) + "\n"
	_, _ = fmt.Fprint(out, divider+strings.Join(lines, "\n")+divider)
}
