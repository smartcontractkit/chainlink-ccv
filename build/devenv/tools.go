package ccv

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/timing"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

/*
This code should be generalized and moved to devenv library after we finish CCIPv1.7 environment!
*/

// TimeTracker is an alias for timing.TimeTracker; existing callers need not change.
type TimeTracker = timing.TimeTracker

// NewTimeTracker creates a new TimeTracker anchored to the current wall-clock time.
func NewTimeTracker(l zerolog.Logger) *TimeTracker { //nolint:gocritic
	return timing.New(l)
}

func PrintCLDFAddresses(in *Cfg) error {
	for _, addr := range in.CLDF.Addresses {
		var refs []datastore.AddressRef
		if err := json.Unmarshal([]byte(addr), &refs); err != nil {
			return fmt.Errorf("failed to unmarshal addresses: %w", err)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		defer w.Flush()

		fmt.Fprintln(w, "Selector\tType\tAddress\tVersion\tQualifier")
		fmt.Fprintln(w, "--------\t----\t-------\t-------\t---------")

		for _, ref := range refs {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", ref.ChainSelector, ref.Type, ref.Address, ref.Version, ref.Qualifier)
		}
	}
	return nil
}
