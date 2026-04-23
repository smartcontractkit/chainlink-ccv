package adapters

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

type VerifierKind string

const (
	CommitteeVerifierKind VerifierKind = "committee"
	CCTPVerifierKind      VerifierKind = "cctp"
	LombardVerifierKind   VerifierKind = "lombard"
)

type MissingIndexerVerifierAddressesError struct {
	Kind          VerifierKind
	ChainSelector uint64
	Qualifier     string
}

func (e *MissingIndexerVerifierAddressesError) Error() string {
	return fmt.Sprintf(
		"no %s verifier addresses found for chain %d with qualifier %q",
		e.Kind,
		e.ChainSelector,
		e.Qualifier,
	)
}

// IndexerConfigAdapter resolves verifier addresses recorded for an indexer from the datastore.
type IndexerConfigAdapter interface {
	// ResolveVerifierAddresses returns the verifier contract addresses of the given kind
	// for the chain selector and qualifier as recorded in the datastore.
	ResolveVerifierAddresses(ds datastore.DataStore, chainSelector uint64, qualifier string, kind VerifierKind) ([]string, error)
}
