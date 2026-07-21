package ccv

import (
	"fmt"
	"os"
	"path/filepath"
)

// addressesFilePath returns the path for the deployed-contract address table.
// It mirrors the uplog convention: an env override, then <cwd>/addresses.txt.
func addressesFilePath() string {
	if p := os.Getenv("CCV_ADDRESSES_FILE"); p != "" {
		return p
	}
	wd, err := os.Getwd()
	if err != nil {
		wd = "."
	}
	return filepath.Join(wd, "addresses.txt")
}

// writeAddressesFile writes the full CLDF address table to path.
func writeAddressesFile(path string, in *Cfg) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create addresses file %s: %w", path, err)
	}
	defer f.Close()
	return WriteCLDFAddresses(f, in)
}

// printUpSummary prints the short, actionable end-state to the (restored)
// terminal after a successful bringup: the endpoints developers use often, plus
// a pointer to the full address table. The verbose firehose stays in the log.
func printUpSummary(in *Cfg, addrPath string) {
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "devenv is up")
	for name, url := range in.AggregatorEndpoints {
		fmt.Fprintf(os.Stdout, "  aggregator %-14s %s\n", name+":", url)
	}
	for i, url := range in.IndexerEndpoints {
		fmt.Fprintf(os.Stdout, "  indexer %-17s %s\n", fmt.Sprintf("#%d:", i+1), url)
	}
	if addrPath != "" {
		fmt.Fprintf(os.Stdout, "  %-24s %s\n", "addresses:", addrPath)
	}
}
