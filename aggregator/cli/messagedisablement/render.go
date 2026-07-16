package messagedisablement

import (
	"fmt"
	"os"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/internal/tablefmt"

	rules "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
)

func renderList(disablementRules []rules.Rule) error {
	if len(disablementRules) == 0 {
		fmt.Println("No message disablement rules found.") //nolint:forbidigo // CLI user output
		return nil
	}
	table := tablefmt.NewPlain(os.Stdout)
	tablefmt.Header(table, []string{"ID", "Type", "Data", "Created At", "Updated At"})
	for _, rule := range disablementRules {
		_, data, err := rules.EncodeRuleData(rule.Data)
		if err != nil {
			return err
		}
		if err := table.Append([]string{
			rule.ID,
			string(rule.Type),
			string(data),
			formatTime(rule.CreatedAt),
			formatTime(rule.UpdatedAt),
		}); err != nil {
			return err
		}
	}
	return table.Render()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02T15:04:05Z07:00")
}
