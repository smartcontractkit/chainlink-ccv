// Command metricsgolden compares the metrics golden files of two checkouts and fails if a metric or label is removed or changed.
//
//	metricsgolden -base <base checkout> -head <head checkout> [-allow-breaking]
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/smartcontractkit/chainlink-ccv/common/metrics/metricsgolden"
)

func main() {
	base := flag.String("base", "", "checkout of the base commit")
	head := flag.String("head", ".", "checkout of the head commit")
	allowBreaking := flag.Bool("allow-breaking", false, "print the violations but exit 0")
	flag.Parse()
	if *base == "" {
		fmt.Fprintln(os.Stderr, "-base is required")
		os.Exit(2)
	}

	n, err := run(*base, *head)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if n == 0 {
		_, _ = fmt.Fprintln(os.Stdout, "metricsgolden: no metric or label is removed or changed")
		return
	}
	if *allowBreaking {
		_, _ = fmt.Fprintf(os.Stdout, "metricsgolden: %d breaking change(s) allowed\n", n)
		return
	}
	_, _ = fmt.Fprintf(os.Stdout, "metricsgolden: %d breaking change(s). Dashboards and alerts can depend on these metrics.\n", n)
	os.Exit(1)
}

// run prints each violation and returns the number of violations.
func run(baseDir, headDir string) (int, error) {
	total := 0
	err := filepath.WalkDir(baseDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != metricsgolden.FileName || filepath.Base(filepath.Dir(path)) != "testdata" {
			return nil
		}
		rel, err := filepath.Rel(baseDir, path)
		if err != nil {
			return err
		}
		base, err := metricsgolden.Load(path)
		if err != nil {
			return err
		}
		head, err := metricsgolden.Load(filepath.Join(headDir, rel))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		for _, v := range metricsgolden.Compare(base, head) {
			_, _ = fmt.Fprintf(os.Stdout, "%s: %s\n", rel, v)
			total++
		}
		return nil
	})
	return total, err
}
