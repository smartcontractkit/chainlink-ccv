package admin

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
)

// AttestationState is the outcome of the per-message freshness check. Unknown is never
// proof that a replay is needed: it disables execution for that target.
type AttestationState string

const (
	AttestationAttested AttestationState = "attested"
	AttestationNotFound AttestationState = "not_found"
	AttestationUnknown  AttestationState = "unknown"
)

// AttestationResult is one message's freshness outcome plus operator-facing detail.
type AttestationResult struct {
	State  AttestationState
	Detail string
}

// attestationCallTimeout bounds every external freshness call so a preview never hangs.
const attestationCallTimeout = 5 * time.Second

// ResultsDialer opens the aggregator's read path for freshness checks.
type ResultsDialer func(address string) (storageaccess.ResultsClient, error)

// dialVerifierClient is the default results dialer: TLS transport, mirroring a secure
// aggregator deployment. A var so tests can substitute a fake; the wiring injects an
// insecure variant when the selected aggregator runs insecure.
var dialVerifierClient ResultsDialer = func(address string) (storageaccess.ResultsClient, error) {
	return storageaccess.DialResultsClient(address, false)
}

// checkAttestations checks each message against the aggregator's read path. An empty
// address means freshness checks are not configured: every result is Unknown, which
// disables execution rather than proving a replay is needed.
func checkAttestations(ctx context.Context, aggregatorAddress string, messageIDs [][]byte, dial ResultsDialer) []AttestationResult {
	if aggregatorAddress == "" {
		results := make([]AttestationResult, len(messageIDs))
		for i := range results {
			results[i] = AttestationResult{AttestationUnknown, "attestation check not configured (no aggregator address)"}
		}
		return results
	}
	return checkAggregatorAttestations(ctx, aggregatorAddress, messageIDs, dial)
}

func checkAggregatorAttestations(ctx context.Context, address string, messageIDs [][]byte, dial ResultsDialer) []AttestationResult {
	results := make([]AttestationResult, len(messageIDs))
	markUnknown := func(detail string) []AttestationResult {
		for i := range results {
			results[i] = AttestationResult{AttestationUnknown, detail}
		}
		return results
	}
	client, err := dial(address)
	if err != nil {
		return markUnknown(err.Error())
	}
	defer func() { _ = client.Close() }()

	callCtx, cancel := context.WithTimeout(ctx, attestationCallTimeout)
	defer cancel()
	entries, err := client.GetVerifierResultsForMessage(callCtx, messageIDs)
	if err != nil {
		return markUnknown("aggregator unreachable: " + err.Error())
	}
	for i := range messageIDs {
		results[i] = aggregatorEntryResult(entries, i)
	}
	return results
}

// aggregatorEntryResult interprets entry i of the batch: only a per-ID NotFound
// proves absence; any other error code leaves the state unknown, so execution
// stays disabled. Only a result with non-empty ccv data proves attestation.
func aggregatorEntryResult(entries []storageaccess.ResultEntry, i int) AttestationResult {
	if i >= len(entries) || !entries[i].Present {
		return AttestationResult{AttestationUnknown, "aggregator response is missing an entry for this message"}
	}
	if entries[i].ErrorCode != int32(codes.OK) {
		if entries[i].ErrorCode == int32(codes.NotFound) {
			return AttestationResult{AttestationNotFound, "aggregator: " + entries[i].ErrorMsg}
		}
		return AttestationResult{
			AttestationUnknown,
			//nolint:gosec // G115: gRPC error codes are always non-negative.
			fmt.Sprintf("aggregator error %s: %s", codes.Code(entries[i].ErrorCode), entries[i].ErrorMsg),
		}
	}
	if len(entries[i].CcvData) > 0 {
		return AttestationResult{AttestationAttested, "aggregator holds ccv data for this message"}
	}
	return AttestationResult{AttestationNotFound, "aggregator returned empty ccv data"}
}
