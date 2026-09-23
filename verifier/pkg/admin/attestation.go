package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
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

// checkNodeAttestations checks each message against the node's first configured
// source: aggregator gRPC preferred, indexer HTTP otherwise. Results align with messageIDs.
func checkNodeAttestations(ctx context.Context, cfg NodeConfig, messageIDs [][]byte) []AttestationResult {
	switch {
	case cfg.AggregatorAddress != "":
		return checkAggregatorAttestations(ctx, cfg.AggregatorAddress, messageIDs)
	case cfg.IndexerURL != "":
		return checkIndexerAttestations(ctx, cfg.IndexerURL, messageIDs)
	default:
		results := make([]AttestationResult, len(messageIDs))
		for i := range results {
			results[i] = AttestationResult{AttestationUnknown, "attestation check not configured for this node (needs aggregator_address or indexer_url)"}
		}
		return results
	}
}

// dialVerifierClient opens the aggregator's read path for freshness checks. A var so
// tests can substitute a fake; the protobuf dialer lives in storageaccess because
// verifier packages must not import the chainlink protos.
var dialVerifierClient = storageaccess.DialResultsClient

func checkAggregatorAttestations(ctx context.Context, address string, messageIDs [][]byte) []AttestationResult {
	results := make([]AttestationResult, len(messageIDs))
	markUnknown := func(detail string) []AttestationResult {
		for i := range results {
			results[i] = AttestationResult{AttestationUnknown, detail}
		}
		return results
	}
	client, err := dialVerifierClient(address)
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

// aggregatorEntryResult interprets entry i of the batch: a per-ID error means "not
// found"; only a result with non-empty ccv data proves attestation.
func aggregatorEntryResult(entries []storageaccess.ResultEntry, i int) AttestationResult {
	if i >= len(entries) || !entries[i].Present {
		return AttestationResult{AttestationUnknown, "aggregator response is missing an entry for this message"}
	}
	if entries[i].ErrorCode != int32(codes.OK) {
		return AttestationResult{AttestationNotFound, "aggregator: " + entries[i].ErrorMsg}
	}
	if len(entries[i].CcvData) > 0 {
		return AttestationResult{AttestationAttested, "aggregator holds ccv data for this message"}
	}
	return AttestationResult{AttestationNotFound, "aggregator returned empty ccv data"}
}

// indexerClient has no client-side timeout; every request carries attestationCallTimeout.
var indexerClient = &http.Client{}

// indexerResultsBody is the minimal decode of the indexer's by-message-ID response;
// only ccv_data presence matters here.
type indexerResultsBody struct {
	Results []struct {
		VerifierResult struct {
			CCVData protocol.ByteSlice `json:"ccv_data"`
		} `json:"verifierResult"`
	} `json:"results"`
}

func checkIndexerAttestations(ctx context.Context, baseURL string, messageIDs [][]byte) []AttestationResult {
	results := make([]AttestationResult, len(messageIDs))
	var wg sync.WaitGroup
	for i, id := range messageIDs {
		wg.Go(func() {
			results[i] = checkIndexerAttestation(ctx, baseURL, id)
		})
	}
	wg.Wait()
	return results
}

// checkIndexerAttestation does GET <base>/v1/verifierresults/<0x messageID>: 200 with
// ccv data is attested, 404 is not found, anything else is unknown.
func checkIndexerAttestation(ctx context.Context, baseURL string, messageID []byte) AttestationResult {
	callCtx, cancel := context.WithTimeout(ctx, attestationCallTimeout)
	defer cancel()
	url := strings.TrimSuffix(baseURL, "/") + "/v1/verifierresults/" + formatMessageID(messageID)
	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, url, nil)
	if err != nil {
		return AttestationResult{AttestationUnknown, "invalid indexer URL: " + err.Error()}
	}
	resp, err := indexerClient.Do(req)
	if err != nil {
		return AttestationResult{AttestationUnknown, "indexer unreachable: " + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		var body indexerResultsBody
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
			return AttestationResult{AttestationUnknown, "indexer response not parseable: " + err.Error()}
		}
		for _, r := range body.Results {
			if len(r.VerifierResult.CCVData) > 0 {
				return AttestationResult{AttestationAttested, "indexer holds ccv data for this message"}
			}
		}
		return AttestationResult{AttestationNotFound, "indexer returned no ccv data"}
	case http.StatusNotFound:
		return AttestationResult{AttestationNotFound, "indexer has no result for this message"}
	default:
		return AttestationResult{AttestationUnknown, fmt.Sprintf("indexer returned status %d", resp.StatusCode)}
	}
}
