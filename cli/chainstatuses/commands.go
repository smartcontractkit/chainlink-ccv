package chainstatuses

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"strconv"

	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"

	chainselectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// ChainStatusStore is the minimal store interface required by the CLI.
type ChainStatusStore interface {
	// List returns all chain status rows.
	List(ctx context.Context) ([]chainstatus.Row, error)
	// SetDisabled sets the disabled flag for the given chain and verifier.
	SetDisabled(ctx context.Context, chainSelector protocol.ChainSelector, verifierID string, disabled bool) error
	// SetFinalizedBlockHeight sets the finalized block height for the given chain and verifier.
	SetFinalizedBlockHeight(ctx context.Context, chainSelector protocol.ChainSelector, verifierID string, height *big.Int) error
}

// Deps holds dependencies for CCV chain-statuses CLI commands.
type Deps struct {
	Logger logger.Logger
	Store  ChainStatusStore
}

// InitCCVChainStatusesCommands returns CLI commands for list, enable, disable, set-finalized-height.
// The caller attaches these under `node ccv chain-statuses` and runs with DB access (e.g. Before: validateDB).
func InitCCVChainStatusesCommands(deps Deps) []cli.Command {
	return buildChainStatusesCommands(func() Deps { return deps })
}

// InitCCVChainStatusesCommandsWithFactory returns the same commands but gets Deps from getDeps at run time.
// Use this when Deps (e.g. Store) can only be built after a Before hook runs (e.g. DB connection).
func InitCCVChainStatusesCommandsWithFactory(getDeps func() Deps) []cli.Command {
	return buildChainStatusesCommands(getDeps)
}

func buildChainStatusesCommands(getDeps func() Deps) []cli.Command {
	return []cli.Command{
		{
			Name:   "list",
			Usage:  "List all chain status rows",
			Action: listActionWithFactory(getDeps),
		},
		{
			Name:   "enable",
			Usage:  "Set disabled = false for the given chain and verifier. Shut down the node before running; changes take effect on next start.",
			Action: enableActionWithFactory(getDeps),
			Flags:  chainSelectorAndVerifierFlags(),
		},
		{
			Name:   "disable",
			Usage:  "Set disabled = true for the given chain and verifier. Shut down the node before running; changes take effect on next start.",
			Action: disableActionWithFactory(getDeps),
			Flags:  chainSelectorAndVerifierFlags(),
		},
		{
			Name:   "set-finalized-height",
			Usage:  "Set finalized_block_height for the given chain and verifier. Shut down the node before running; changes take effect on next start.",
			Action: setFinalizedHeightActionWithFactory(getDeps),
			Flags: append(chainSelectorAndVerifierFlags(),
				cli.Uint64Flag{
					Name:     "block-height",
					Usage:    "Finalized block height to set",
					Required: true,
				},
			),
		},
	}
}

func chainSelectorAndVerifierFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:     "chain-selector",
			Usage:    "Chain selector (e.g. from chain-selectors)",
			Required: true,
		},
		cli.StringFlag{
			Name:     "verifier-id",
			Usage:    "Verifier ID",
			Required: true,
		},
	}
}

func listActionWithFactory(getDeps func() Deps) func(c *cli.Context) error {
	return func(c *cli.Context) error {
		deps := getDeps()
		ctx := context.Background()
		rows, err := deps.Store.List(ctx)
		if err != nil {
			deps.Logger.Errorw("list chain statuses failed", "error", err)
			return err
		}
		return renderList(rows)
	}
}

func chainSelectorFromContext(c *cli.Context) (protocol.ChainSelector, error) {
	s := c.String("chain-selector")
	if s == "" {
		return 0, fmt.Errorf("--chain-selector is required")
	}
	return ParseChainSelector(s)
}

func enableActionWithFactory(getDeps func() Deps) func(c *cli.Context) error {
	return func(c *cli.Context) error {
		deps := getDeps()
		chainSelector, err := chainSelectorFromContext(c)
		if err != nil {
			return err
		}
		verifierID := c.String("verifier-id")
		ctx := context.Background()
		if err := deps.Store.SetDisabled(ctx, chainSelector, verifierID, false); err != nil {
			deps.Logger.Errorw("enable chain status failed", "chain_selector", chainSelector, "verifier_id", verifierID, "error", err)
			return err
		}
		fmt.Printf("Chain %s (Chain Selector %d) (verifier %s) enabled.\n", chainNameFromSelector(chainSelector), chainSelector, verifierID) //nolint:forbidigo // CLI user output
		return nil
	}
}

func chainNameFromSelector(chainSelector protocol.ChainSelector) string {
	name, err := chainselectors.GetChainNameFromSelector(uint64(chainSelector))
	if err != nil {
		return "unknown"
	}
	return name
}

func disableActionWithFactory(getDeps func() Deps) func(c *cli.Context) error {
	return func(c *cli.Context) error {
		deps := getDeps()
		chainSelector, err := chainSelectorFromContext(c)
		if err != nil {
			return err
		}
		verifierID := c.String("verifier-id")
		ctx := context.Background()
		if err := deps.Store.SetDisabled(ctx, chainSelector, verifierID, true); err != nil {
			deps.Logger.Errorw("disable chain status failed", "chain_selector", chainSelector, "verifier_id", verifierID, "error", err)
			return err
		}
		fmt.Printf("Chain %s (Chain Selector %d) (verifier %s) disabled.\n", chainNameFromSelector(chainSelector), chainSelector, verifierID) //nolint:forbidigo // CLI user output
		return nil
	}
}

func setFinalizedHeightActionWithFactory(getDeps func() Deps) func(c *cli.Context) error {
	return func(c *cli.Context) error {
		deps := getDeps()
		chainSelector, err := chainSelectorFromContext(c)
		if err != nil {
			return err
		}
		verifierID := c.String("verifier-id")
		blockHeightU64 := c.Uint64("block-height")
		height := new(big.Int).SetUint64(blockHeightU64)
		ctx := context.Background()
		if err := deps.Store.SetFinalizedBlockHeight(ctx, chainSelector, verifierID, height); err != nil {
			deps.Logger.Errorw("set finalized block height failed", "chain_selector", chainSelector, "verifier_id", verifierID, "error", err)
			return err
		}
		fmt.Printf("Chain %s (Chain Selector %d) (verifier %s) finalized_block_height set to %s.\n", chainNameFromSelector(chainSelector), chainSelector, verifierID, height.String()) //nolint:forbidigo // CLI user output
		return nil
	}
}

func renderList(rows []chainstatus.Row) error {
	if len(rows) == 0 {
		fmt.Println("No chain status rows found.") //nolint:forbidigo // CLI user output
		return nil
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoFormatHeaders(false)
	table.SetHeader([]string{"Chain", "Chain Selector", "verifier_id", "finalized_block_height", "disabled", "updated_at"})
	table.SetBorder(false)
	data := make([][]string, 0, len(rows))
	for _, r := range rows {
		heightStr := "0"
		if r.FinalizedBlockHeight != nil {
			heightStr = r.FinalizedBlockHeight.String()
		}
		disabledStr := "false"
		if r.Disabled {
			disabledStr = "true"
		}
		chainName := chainNameFromSelector(r.ChainSelector)
		data = append(data, []string{
			chainName,
			fmt.Sprintf("%d", r.ChainSelector),
			r.VerifierID,
			heightStr,
			disabledStr,
			r.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	table.AppendBulk(data)
	table.Render()
	return nil
}

// ParseChainSelector parses a chain selector from string (for tests).
func ParseChainSelector(s string) (protocol.ChainSelector, error) {
	u, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid chain selector %q: %w", s, err)
	}
	return protocol.ChainSelector(u), nil
}
