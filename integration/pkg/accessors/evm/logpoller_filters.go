package evm

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
)

// filterNameID is the log poller filter-name ID every verifier filter starts with.
const filterNameID = "ccv-verifier"

// onRampSuffixLen is the length of the on-ramp address ("0x" plus 40 hex characters) that ends every
// verifier filter name.
const onRampSuffixLen = 2 * (1 + common.AddressLength)

// verifierFilterName is the name of a verifier's filter for one on-ramp.
func verifierFilterName(verifierID string, onRamp common.Address) string {
	return logpoller.FilterName(filterNameID, verifierID, onRamp.Hex())
}

// verifierFilterPrefix is what every filter name of the verifier starts with. It is built by the same
// FilterName call as the full name, with an empty last argument, so the two cannot disagree.
func verifierFilterPrefix(verifierID string) string {
	return logpoller.FilterName(filterNameID, verifierID, "")
}

// isVerifierFilterName reports whether name is one of the verifier's filter names. The prefix alone is
// not enough: verifier IDs may contain ':', so "v:x"'s filters start with "v"'s prefix. The rest of the
// name must be exactly an on-ramp address.
func isVerifierFilterName(name, verifierID string) bool {
	prefix := verifierFilterPrefix(verifierID)
	suffix, ok := strings.CutPrefix(name, prefix)
	return ok && len(suffix) == onRampSuffixLen && common.IsHexAddress(suffix)
}

// staleVerifierFilters returns the names of the verifier's stored filters on the ORM's chain, except
// keep (pass "" to keep none), in name order. Other verifiers' filters and other shapes are never
// returned.
func staleVerifierFilters(ctx context.Context, orm logpoller.ORM, verifierID, keep string) ([]string, error) {
	stored, err := orm.LoadFilters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load stored log poller filters: %w", err)
	}
	var names []string
	for name := range stored {
		if name != keep && isVerifierFilterName(name, verifierID) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, nil
}

// cleanVerifierFilters deletes the verifier's stored filters for the ORM's chain. It is for a verifier
// that starts without the LogPoller, where nothing else would unregister them. Logs and blocks stay;
// the next reader start deals with those. Every failure is returned for the caller to log, including a
// missing evm schema. It stops once ctx is done and reports the filters it did not reach.
func cleanVerifierFilters(ctx context.Context, orm logpoller.ORM, verifierID string) error {
	names, err := staleVerifierFilters(ctx, orm, verifierID, "")
	if err != nil {
		return err
	}
	var errs []error
	for i, name := range names {
		if err := ctx.Err(); err != nil {
			errs = append(errs, fmt.Errorf("stopped before deleting log poller filters %v: %w", names[i:], err))
			break
		}
		if err := orm.DeleteFilter(ctx, name); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete log poller filter %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
