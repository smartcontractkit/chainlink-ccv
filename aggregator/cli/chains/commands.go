package chains

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"

	chainselectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/chaindisable"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Deps holds dependencies for the aggregator chains CLI commands.
type Deps struct {
	Logger    logger.Logger
	Store     chaindisable.Store
	Committee *model.Committee
}

// InitChainsCommands returns CLI commands for disable, enable, list, get.
func InitChainsCommands(deps Deps) []cli.Command {
	return buildChainsCommands(func() Deps { return deps })
}

// InitChainsCommandsWithFactory returns the same commands but gets Deps lazily at run time.
func InitChainsCommandsWithFactory(getDeps func() Deps) []cli.Command {
	return buildChainsCommands(getDeps)
}

func buildChainsCommands(getDeps func() Deps) []cli.Command {
	return []cli.Command{
		{
			Name:   "disable",
			Usage:  "Disable chain processing for the given source/destination selectors",
			Action: setStatusActionWithFactory(getDeps, true),
			Flags:  laneSideFlags(),
		},
		{
			Name:   "enable",
			Usage:  "Re-enable chain processing for the given source/destination selectors",
			Action: setStatusActionWithFactory(getDeps, false),
			Flags:  laneSideFlags(),
		},
		{
			Name:   "list",
			Usage:  "List all chain status rows",
			Action: listActionWithFactory(getDeps),
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "only-disabled",
					Usage: "Show only disabled chains",
				},
			},
		},
		{
			Name:   "get",
			Usage:  "Get the status for a specific chain selector and lane side",
			Action: getActionWithFactory(getDeps),
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:     "source",
					Usage:    "Source chain selector",
					Required: false,
				},
				cli.StringFlag{
					Name:     "destination",
					Usage:    "Destination chain selector",
					Required: false,
				},
			},
		},
	}
}

func laneSideFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:  "source",
			Usage: "Comma-separated source chain selectors",
		},
		cli.StringFlag{
			Name:  "destination",
			Usage: "Comma-separated destination chain selectors",
		},
		cli.BoolFlag{
			Name:  "all",
			Usage: "Apply to all known source and destination chains from the committee config",
		},
	}
}

func setStatusActionWithFactory(getDeps func() Deps, disabled bool) func(c *cli.Context) error {
	return func(c *cli.Context) error {
		deps := getDeps()
		ctx := context.Background()

		useAll := c.Bool("all")
		sourceStr := c.String("source")
		destStr := c.String("destination")

		if !useAll && sourceStr == "" && destStr == "" {
			return fmt.Errorf("one of --source, --destination, or --all is required")
		}

		action := "disabled"
		if !disabled {
			action = "enabled"
		}

		if useAll {
			allSources := committeeSourceSelectors(deps.Committee)
			allDests := committeeDestSelectors(deps.Committee)
			if err := deps.Store.BatchSetStatus(ctx, chaindisable.LaneSideSource, allSources, disabled); err != nil {
				deps.Logger.Errorw("failed to set source statuses", "error", err)
				return err
			}
			if err := deps.Store.BatchSetStatus(ctx, chaindisable.LaneSideDestination, allDests, disabled); err != nil {
				deps.Logger.Errorw("failed to set destination statuses", "error", err)
				return err
			}
			fmt.Printf("All %d source(s) and %d destination(s) %s.\n", len(allSources), len(allDests), action) //nolint:forbidigo // CLI user output
			return nil
		}

		if sourceStr != "" {
			selectors, err := parseSelectors(sourceStr)
			if err != nil {
				return fmt.Errorf("invalid --source: %w", err)
			}
			if err := deps.Store.BatchSetStatus(ctx, chaindisable.LaneSideSource, selectors, disabled); err != nil {
				deps.Logger.Errorw("failed to set source statuses", "error", err)
				return err
			}
			fmt.Printf("Source selector(s) %s %s.\n", sourceStr, action) //nolint:forbidigo // CLI user output
		}

		if destStr != "" {
			selectors, err := parseSelectors(destStr)
			if err != nil {
				return fmt.Errorf("invalid --destination: %w", err)
			}
			if err := deps.Store.BatchSetStatus(ctx, chaindisable.LaneSideDestination, selectors, disabled); err != nil {
				deps.Logger.Errorw("failed to set destination statuses", "error", err)
				return err
			}
			fmt.Printf("Destination selector(s) %s %s.\n", destStr, action) //nolint:forbidigo // CLI user output
		}

		return nil
	}
}

func listActionWithFactory(getDeps func() Deps) func(c *cli.Context) error {
	return func(c *cli.Context) error {
		deps := getDeps()
		ctx := context.Background()

		var (
			statuses []chaindisable.ChainStatus
			err      error
		)
		if c.Bool("only-disabled") {
			statuses, err = deps.Store.ListDisabled(ctx)
		} else {
			statuses, err = deps.Store.List(ctx)
		}
		if err != nil {
			deps.Logger.Errorw("list chain statuses failed", "error", err)
			return err
		}
		return renderList(statuses)
	}
}

func getActionWithFactory(getDeps func() Deps) func(c *cli.Context) error {
	return func(c *cli.Context) error {
		deps := getDeps()
		ctx := context.Background()

		sourceStr := c.String("source")
		destStr := c.String("destination")
		if sourceStr == "" && destStr == "" {
			return fmt.Errorf("one of --source or --destination is required")
		}

		var statuses []chaindisable.ChainStatus
		if sourceStr != "" {
			sel, err := parseSelector(sourceStr)
			if err != nil {
				return fmt.Errorf("invalid --source: %w", err)
			}
			s, err := deps.Store.Get(ctx, chaindisable.LaneSideSource, sel)
			if err != nil {
				deps.Logger.Errorw("get source chain status failed", "error", err)
				return err
			}
			if s != nil {
				statuses = append(statuses, *s)
			} else {
				statuses = append(statuses, chaindisable.ChainStatus{ChainSelector: sel, Side: chaindisable.LaneSideSource, Disabled: false})
			}
		}
		if destStr != "" {
			sel, err := parseSelector(destStr)
			if err != nil {
				return fmt.Errorf("invalid --destination: %w", err)
			}
			s, err := deps.Store.Get(ctx, chaindisable.LaneSideDestination, sel)
			if err != nil {
				deps.Logger.Errorw("get destination chain status failed", "error", err)
				return err
			}
			if s != nil {
				statuses = append(statuses, *s)
			} else {
				statuses = append(statuses, chaindisable.ChainStatus{ChainSelector: sel, Side: chaindisable.LaneSideDestination, Disabled: false})
			}
		}
		return renderList(statuses)
	}
}

func renderList(statuses []chaindisable.ChainStatus) error {
	if len(statuses) == 0 {
		fmt.Println("No chain status rows found.") //nolint:forbidigo // CLI user output
		return nil
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoFormatHeaders(false)
	table.SetHeader([]string{"Chain", "Selector", "Side", "Disabled", "Updated At"})
	table.SetBorder(false)
	for _, s := range statuses {
		name := chainNameFromSelector(s.ChainSelector)
		disabledStr := "false"
		if s.Disabled {
			disabledStr = "true"
		}
		updatedAt := ""
		if !s.UpdatedAt.IsZero() {
			updatedAt = s.UpdatedAt.Format("2006-01-02T15:04:05Z07:00")
		}
		table.Append([]string{name, fmt.Sprintf("%d", s.ChainSelector), string(s.Side), disabledStr, updatedAt})
	}
	table.Render()
	return nil
}

func chainNameFromSelector(sel uint64) string {
	name, err := chainselectors.GetChainNameFromSelector(sel)
	if err != nil {
		return "unknown"
	}
	return name
}

func committeeSourceSelectors(committee *model.Committee) []uint64 {
	if committee == nil {
		return nil
	}
	selectors := make([]uint64, 0, len(committee.QuorumConfigs))
	for selStr := range committee.QuorumConfigs {
		sel, err := strconv.ParseUint(selStr, 10, 64)
		if err != nil {
			continue
		}
		selectors = append(selectors, sel)
	}
	return selectors
}

func committeeDestSelectors(committee *model.Committee) []uint64 {
	if committee == nil {
		return nil
	}
	selectors := make([]uint64, 0, len(committee.DestinationVerifiers))
	for selStr := range committee.DestinationVerifiers {
		sel, err := strconv.ParseUint(selStr, 10, 64)
		if err != nil {
			continue
		}
		selectors = append(selectors, sel)
	}
	return selectors
}

func parseSelectors(s string) ([]uint64, error) {
	parts := strings.Split(s, ",")
	selectors := make([]uint64, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		sel, err := parseSelector(p)
		if err != nil {
			return nil, err
		}
		selectors = append(selectors, sel)
	}
	if len(selectors) == 0 {
		return nil, fmt.Errorf("no valid selectors provided")
	}
	return selectors, nil
}

func parseSelector(s string) (uint64, error) {
	u, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid chain selector %q: %w", s, err)
	}
	return u, nil
}
