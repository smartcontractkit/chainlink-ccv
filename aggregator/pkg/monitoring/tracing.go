package monitoring

import (
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// Span event names emitted across the aggregator write/aggregation pipeline.
// Kept as constants so debugging/alerting tooling can match on them without
// risking drift from ad-hoc string literals at each call site.
const (
	EventDisablementRejected = "disablement_rejected"
	EventSignatureValidated  = "signature_validated"
	EventVerificationSaved   = "verification_saved"
	EventAggregationEnqueued = "aggregation_enqueued"
	EventAggregationSkipped  = "aggregation_skipped_existing_quorum"
	EventQuorumNotMet        = "quorum_not_met"
	EventReportSubmitted     = "report_submitted"
	EventReportUnexportable  = "report_unexportable"
	// EventAggregationAlreadySubmitted fires when a concurrent worker already
	// inserted the identical aggregated report first (ON CONFLICT DO NOTHING) -
	// not an error.
	EventAggregationAlreadySubmitted = "aggregation_already_submitted"
)

// WriteSpanName is the span opened for each WriteCommitVerifierNodeResult call
// (both standalone and as a leaf of BatchWriteCommitVerifierNodeResult).
const WriteSpanName = "aggregator.write"

// BatchWriteSpanName is the parent span opened for BatchWriteCommitVerifierNodeResult,
// wrapping the fan-out of per-item WriteSpanName children.
const BatchWriteSpanName = "aggregator.batch_write"

// ReadSpanName is the span opened for ReadCommitVerifierNodeResult.
const ReadSpanName = "aggregator.read"

// GetMessagesSinceSpanName is the span opened for GetMessagesSince.
const GetMessagesSinceSpanName = "aggregator.get_messages_since"

// GetVerifierResultsForMessageSpanName is the span opened for GetVerifierResultsForMessage.
const GetVerifierResultsForMessageSpanName = "aggregator.get_verifier_results_for_message"

// AggregationWorkSpanName is the worker span, parented from the enqueueing write traceparent.
// If that traceparent is missing, StartMessageSpan falls back to the message's deterministic trace.
const AggregationWorkSpanName = "aggregator.aggregation_work"

// OrphanRecoverySpanName is the span opened per orphan-recovery scan tick.
const OrphanRecoverySpanName = "aggregator.orphan_recovery"

// MessageIDToBytes32 converts an aggregator model.MessageID ([]byte) into a
// protocol.Bytes32 suitable for tracing.TraceIDForMessage, copying up to 32
// bytes and zero-padding/truncating as needed.
func MessageIDToBytes32(id []byte) protocol.Bytes32 {
	var b protocol.Bytes32
	copy(b[:], id)
	return b
}
