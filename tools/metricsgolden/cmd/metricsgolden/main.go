// Command metricsgolden compares two metrics golden files and fails if a metric or label is removed or changed.
//
//	metricsgolden -base <base golden file> -head <head golden file> [-allow-breaking]
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"

	"github.com/smartcontractkit/chainlink-ccv/common/metrics/metricsgolden"
)

func main() {
	basePath := flag.String("base", "", "golden file of the base commit; a missing file means no metrics")
	headPath := flag.String("head", "", "golden file of the head commit")
	allowBreaking := flag.Bool("allow-breaking", false, "print the violations but exit 0")
	flag.Parse()
	if *basePath == "" || *headPath == "" {
		fmt.Fprintln(os.Stderr, "-base and -head are required")
		os.Exit(2)
	}

	base, err := metricsgolden.Load(*basePath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	head, err := metricsgolden.Load(*headPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	violations := metricsgolden.Compare(base, head)
	for _, v := range violations {
		_, _ = fmt.Fprintln(os.Stdout, v)
	}
	switch {
	case len(violations) == 0:
		_, _ = fmt.Fprintln(os.Stdout, "metricsgolden: no metric or label is removed or changed")
	case *allowBreaking:
		_, _ = fmt.Fprintf(os.Stdout, "metricsgolden: %d breaking change(s) allowed\n", len(violations))
	default:
		_, _ = fmt.Fprintf(os.Stdout, "metricsgolden: %d breaking change(s). Dashboards and alerts can depend on these metrics.\n", len(violations))
		os.Exit(1)
	}
}
