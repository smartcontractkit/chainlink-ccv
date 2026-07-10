package messagedisablement

import (
	"fmt"
	"os"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"

	rules "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
)

func renderList(disablementRules []rules.Rule) error {
	if len(disablementRules) == 0 {
		fmt.Println("No message disablement rules found.") //nolint:forbidigo // CLI user output
		return nil
	}

	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
			Borders: tw.BorderNone,
		})),
		tablewriter.WithConfig(tablewriter.Config{
			Header: tw.CellConfig{
				Formatting: tw.CellFormatting{
					AutoFormat: tw.Off,
				},
			},
		}),
	)
	table.Header("ID", "Type", "Data", "Created At", "Updated At")

	for _, rule := range disablementRules {
		_, data, err := rules.EncodeRuleData(rule.Data)
		if err != nil {
			return err
		}
		table.Append([]string{
			rule.ID,
			string(rule.Type),
			string(data),
			formatTime(rule.CreatedAt),
			formatTime(rule.UpdatedAt),
		})
	}

	if err := table.Render(); err != nil {
		fmt.Errorf("failed to render disablement rules table: %w", err)
	}

	return nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02T15:04:05Z07:00")
}
