package messagedisablement

import (
	"fmt"
	"os"
	"time"

	"github.com/olekukonko/tablewriter"

	rules "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/messagedisablement"
)

func renderList(disablementRules []rules.Rule) error {
	if len(disablementRules) == 0 {
		fmt.Println("No message disablement rules found.") //nolint:forbidigo // CLI user output
		return nil
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoFormatHeaders(false)
	table.SetHeader([]string{"ID", "Type", "Data", "Created At", "Updated At"})
	table.SetBorder(false)
	for _, rule := range disablementRules {
		table.Append([]string{
			rule.ID,
			string(rule.Type),
			string(rule.Data),
			formatTime(rule.CreatedAt),
			formatTime(rule.UpdatedAt),
		})
	}
	table.Render()
	return nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02T15:04:05Z07:00")
}
