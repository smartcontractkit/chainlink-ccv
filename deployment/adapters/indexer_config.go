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

type IndexerConfigAdapter interface {
	ResolveVerifierAddresses(ds datastore.DataStore, chainSelector uint64, qualifier string, kind VerifierKind) ([]string, error)
}
