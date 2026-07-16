package tablefmt

import (
	"io"
	"strings"
	"text/tabwriter"
)

// Table is a tiny wrapper around the standard library's tabwriter.
type Table struct {
	writer *tabwriter.Writer
	header []string
	rows   [][]string
}

// NewPlain returns a whitespace-aligned CLI table.
func NewPlain(w io.Writer) *Table {
	return newTable(w)
}

// NewKeyValue returns a left-aligned key/value table with no separators.
func NewKeyValue(w io.Writer) *Table {
	return newTable(w)
}

func newTable(w io.Writer) *Table {
	return &Table{writer: tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)}
}

// Header sets column headers from a string slice.
func Header(table *Table, cols []string) {
	table.header = append([]string(nil), cols...)
}

// Append adds one row to the table.
func (t *Table) Append(row []string) error {
	t.rows = append(t.rows, append([]string(nil), row...))
	return nil
}

// Bulk adds multiple rows to the table.
func (t *Table) Bulk(rows [][]string) error {
	for _, row := range rows {
		if err := t.Append(row); err != nil {
			return err
		}
	}
	return nil
}

// Render writes the table.
func (t *Table) Render() error {
	if len(t.header) > 0 {
		if _, err := io.WriteString(t.writer, joinRow(t.header)+"\n"); err != nil {
			return err
		}
	}
	for _, row := range t.rows {
		if _, err := io.WriteString(t.writer, joinRow(row)+"\n"); err != nil {
			return err
		}
	}
	return t.writer.Flush()
}

func joinRow(row []string) string {
	return strings.Join(row, "\t")
}
