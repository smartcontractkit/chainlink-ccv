package common

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// NewTokenCombinationFromRefs builds a TokenCombination directly from two
// deployed pool refs (one per chain). Pool type and version come from the
// refs; the qualifiers are stamped verbatim so the generated
// LocalPoolAddressRef/RemotePoolAddressRef resolve to the deployed pools.
// CCV qualifier lists drive the expected counts; an empty list assumes a
// single default committee.
func NewTokenCombinationFromRefs(
	localPoolRef, remotePoolRef datastore.AddressRef,
	localCCVQualifiers, remoteCCVQualifiers []string,
) (TokenCombination, error) {
	if localPoolRef.Version == nil || remotePoolRef.Version == nil {
		return TokenCombination{}, fmt.Errorf("pool refs must carry non-nil versions")
	}
	if localPoolRef.Qualifier == "" || remotePoolRef.Qualifier == "" {
		return TokenCombination{}, fmt.Errorf("pool refs must carry non-empty qualifiers")
	}
	combo := newTokenCombination(
		string(localPoolRef.Type), localPoolRef.Version.String(), localCCVQualifiers,
		string(remotePoolRef.Type), remotePoolRef.Version.String(), remoteCCVQualifiers,
	)
	combo.localPoolQualifier = localPoolRef.Qualifier
	combo.remotePoolQualifier = remotePoolRef.Qualifier
	return combo, nil
}
