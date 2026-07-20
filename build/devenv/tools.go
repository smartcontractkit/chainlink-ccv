package ccv

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// PrintCLDFAddresses writes the deployed contract address table to stdout.
func PrintCLDFAddresses(in *Cfg) error {
	return WriteCLDFAddresses(os.Stdout, in)
}

// WriteCLDFAddresses writes the deployed contract address table to w.
func WriteCLDFAddresses(out io.Writer, in *Cfg) error {
	for _, addr := range in.CLDF.Addresses {
		var refs []datastore.AddressRef
		if err := json.Unmarshal([]byte(addr), &refs); err != nil {
			return fmt.Errorf("failed to unmarshal addresses: %w", err)
		}
		w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
		defer w.Flush()

		fmt.Fprintln(w, "Selector\tType\tAddress\tVersion\tQualifier")
		fmt.Fprintln(w, "--------\t----\t-------\t-------\t---------")

		for _, ref := range refs {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", ref.ChainSelector, ref.Type, ref.Address, ref.Version, ref.Qualifier)
		}
	}
	return nil
}
