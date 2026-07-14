package tablefmt

import (
	"io"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

// NewPlain returns a borderless CLI table matching the legacy tablewriter v0.0.5 style.
func NewPlain(w io.Writer) *tablewriter.Table {
	return tablewriter.NewTable(w,
		tablewriter.WithHeaderAutoFormat(tw.Off),
		tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
			Borders: tw.BorderNone,
			Settings: tw.Settings{
				Separators: tw.SeparatorsNone,
				Lines:      tw.LinesNone,
			},
		})),
	)
}

// NewKeyValue returns a borderless left-aligned table with no column separators.
func NewKeyValue(w io.Writer) *tablewriter.Table {
	return tablewriter.NewTable(w,
		tablewriter.WithHeaderAutoFormat(tw.Off),
		tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
			Borders: tw.BorderNone,
			Settings: tw.Settings{
				Separators: tw.Separators{BetweenColumns: tw.Off},
				Lines:      tw.LinesNone,
			},
		})),
		tablewriter.WithConfig(tablewriter.Config{
			Row: tw.CellConfig{Alignment: tw.CellAlignment{Global: tw.AlignLeft}},
		}),
	)
}

// Header sets column headers from a string slice.
func Header(table *tablewriter.Table, cols []string) {
	args := make([]any, len(cols))
	for i, col := range cols {
		args[i] = col
	}
	table.Header(args...)
}
