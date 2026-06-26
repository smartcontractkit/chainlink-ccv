// Package viz provides synthetic CCIP message trace data for local dev and testing.
// The trace represents a complete CCIP message lifecycle:
// finalization → committee verification (quorum) → aggregation → token verification → indexing → execution.
package viz

import (
	"encoding/json"
	"time"
)

const (
	MessageID = "0x1fedb7ff3a17716f4f3beb2c8e2f3558a76fba88f69fc5f9de5578f5f434a1f2"
)

type Trace struct {
	TraceID   string             `json:"traceID"`
	Spans     []Span             `json:"spans"`
	Processes map[string]Process `json:"processes"`
	Warnings  any                `json:"warnings"`
}

type Span struct {
	TraceID       string      `json:"traceID"`
	SpanID        string      `json:"spanID"`
	OperationName string      `json:"operationName"`
	References    []Reference `json:"references"`
	StartTime     int64       `json:"startTime"`
	Duration      int64       `json:"duration"`
	ProcessID     string      `json:"processID"`
	Warnings      []string    `json:"warnings,omitempty"`
	Tags          []KeyValue  `json:"tags"`
	Logs          []SpanLog   `json:"logs"`
}

type Reference struct {
	RefType string `json:"refType"`
	TraceID string `json:"traceID"`
	SpanID  string `json:"spanID"`
}

type Process struct {
	ServiceName string     `json:"serviceName"`
	Tags        []KeyValue `json:"tags"`
}

type SpanLog struct {
	Timestamp int64      `json:"timestamp"`
	Fields    []KeyValue `json:"fields"`
}

type KeyValue struct {
	Key   string `json:"key"`
	Type  string `json:"type"`
	Value any    `json:"value"`
}

type CCIPMessageSent struct {
	Data                any       `json:"data"`
	Sender              string    `json:"sender"`
	Version             int       `json:"version"`
	DestBlob            any       `json:"destBlob"`
	FeeToken            string    `json:"feeToken"`
	Receipts            []Receipt `json:"receipts"`
	Receiver            string    `json:"receiver"`
	MessageID           string    `json:"messageId"`
	TokenAmounts        []any     `json:"tokenAmounts"`
	FinalityDepth       int       `json:"finalityDepth"`
	OnRampAddress       string    `json:"onRampAddress"`
	EncodedMessage      string    `json:"encodedMessage"`
	OffRampAddress      string    `json:"offRampAddress"`
	SequenceNumber      int       `json:"sequenceNumber"`
	DestChainSelector   string    `json:"destChainSelector"`
	ExecutionGasLimit   int       `json:"executionGasLimit"`
	CCVAndExecutorHash  string    `json:"ccvAndExecutorHash"`
	CCIPReceiveGasLimit int       `json:"ccipReceiveGasLimit"`
	SourceChainSelector string    `json:"sourceChainSelector"`
}

type Receipt struct {
	Issuer            string `json:"issuer"`
	ExtraArgs         string `json:"extraArgs"`
	DestGasLimit      int    `json:"destGasLimit"`
	FeeTokenAmount    string `json:"feeTokenAmount"`
	DestBytesOverhead int    `json:"destBytesOverhead"`
}

type ExecutionStateChanged struct {
	State               int    `json:"state"`
	MessageID           string `json:"messageId"`
	ReturnData          string `json:"returnData"`
	MessageNumber       int    `json:"messageNumber"`
	SourceChainSelector string `json:"sourceChainSelector"`
}

func BuildTrace() Trace {
	t0 := MustMicros("2026-06-01T15:48:29Z")

	msg := CCIPMessageSentData()
	stateChanged := ExecutionStateChangedData()

	return Trace{
		TraceID: MessageID,
		Spans: []Span{
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000001",
				OperationName: "ccip.message",
				References:    []Reference{},
				StartTime:     t0,
				Duration:      Millis(13100),
				ProcessID:     "p1",
				Warnings: []string{
					"mock trace",
					"hardcoded CCIP trace",
					"contains synthetic warnings and errors for UI/testing",
					"committee-verifier/nop-4 span ends after its parent verification span",
					"executor-1 span ends after parent execution span",
				},
				Tags: []KeyValue{
					StrTag("span.kind", "server"),
					StrTag("service.version", "mock-ccip-jaeger-v1"),
					StrTag("ccip.message_id", MessageID),
					IntTag("ccip.sequence_number", msg.SequenceNumber),
					StrTag("ccip.source_chain_selector", msg.SourceChainSelector),
					StrTag("ccip.dest_chain_selector", msg.DestChainSelector),
					StrTag("ccip.sender", msg.Sender),
					StrTag("ccip.receiver", msg.Receiver),
					StrTag("ccip.on_ramp", msg.OnRampAddress),
					StrTag("ccip.off_ramp", msg.OffRampAddress),
					StrTag("ccip.fee_token", msg.FeeToken),
					IntTag("ccip.receipts_count", len(msg.Receipts)),
					IntTag("ccip.execution_gas_limit", msg.ExecutionGasLimit),
					BoolTag("error", false),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0, []KeyValue{
						StrTag("event", "trace.started"),
						StrTag("message", "CCIP message lifecycle started"),
					}),
					SpanLogEntry(t0, []KeyValue{
						StrTag("event", "CCIPMessageSent"),
						StrTag("payload", MustJSONString(msg)),
					}),
					SpanLogEntry(t0+Millis(13100), []KeyValue{
						StrTag("event", "trace.completed"),
						StrTag("message", "CCIP message lifecycle completed"),
					}),
				},
			},
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000002",
				OperationName: "ccip.finalization",
				References:    ChildOf("0000000000000001"),
				StartTime:     t0,
				Duration:      Seconds(4),
				ProcessID:     "p2",
				Warnings: []string{
					"finalityDepth is 0; finalization span is synthetic",
				},
				Tags: []KeyValue{
					StrTag("span.kind", "internal"),
					StrTag("phase", "finalization"),
					StrTag("ccip.message_id", MessageID),
					IntTag("ccip.finality_depth", msg.FinalityDepth),
					StrTag("blockchain.source_chain_selector", msg.SourceChainSelector),
					BoolTag("error", false),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0, []KeyValue{
						StrTag("event", "finalization.started"),
						StrTag("message", "Waiting for source-chain finality"),
					}),
					SpanLogEntry(t0+Seconds(1), []KeyValue{
						StrTag("event", "context"),
						StrTag("source_chain_selector", msg.SourceChainSelector),
						IntTag("sequence_number", msg.SequenceNumber),
						IntTag("finality_depth", msg.FinalityDepth),
					}),
					SpanLogEntry(t0+Seconds(4), []KeyValue{
						StrTag("event", "finalization.completed"),
						StrTag("message", "Message considered finalized for mock trace"),
					}),
				},
			},
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000003",
				OperationName: "ccip.verification",
				References:    ChildOf("0000000000000001"),
				StartTime:     t0 + Seconds(4),
				Duration:      Millis(3800),
				ProcessID:     "p1",
				Warnings: []string{
					"committee-verifier/nop-5 did not submit",
					"committee-verifier/nop-4 submitted an error after quorum was reached",
					"child span committee-verifier/nop-4 ends after parent verification span",
				},
				Tags: []KeyValue{
					StrTag("span.kind", "internal"),
					StrTag("phase", "verification"),
					StrTag("ccip.message_id", MessageID),
					StrTag("verification.status", "success"),
					StrTag("verification.quorum.status", "reached"),
					IntTag("verification.quorum.required", 3),
					IntTag("verification.committee.total", 5),
					IntTag("verification.committee.successful", 3),
					IntTag("verification.committee.failed", 1),
					IntTag("verification.committee.missing", 1),
					StrTag("verification.quorum_reached_by", "nop-1,nop-2,nop-3"),
					StrTag("verification.missing_nops", "nop-5"),
					BoolTag("error", false),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0+Seconds(4), []KeyValue{
						StrTag("event", "verification.started"),
						StrTag("message", "Starting message verification"),
					}),
					SpanLogEntry(t0+Millis(6100), []KeyValue{
						StrTag("event", "committee.quorum_reached"),
						StrTag("message", "Committee quorum reached after 3 successful submissions"),
						IntTag("successful_submissions", 3),
						IntTag("required_submissions", 3),
						StrTag("nodes", "nop-1,nop-2,nop-3"),
					}),
					SpanLogEntry(t0+Millis(6100), []KeyValue{
						StrTag("event", "aggregator.report_pushed"),
						StrTag("message", "Aggregator pushed merkle root report after quorum"),
					}),
					SpanLogEntry(t0+Millis(7800), []KeyValue{
						StrTag("event", "verification.completed"),
						StrTag("message", "Verification completed; token verifier pushed result to storage"),
					}),
				},
			},
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000011",
				OperationName: "committee-verifier.verify/nop-1",
				References:    ChildOf("0000000000000003"),
				StartTime:     t0 + Millis(4050),
				Duration:      Millis(1200),
				ProcessID:     "p3",
				Tags: []KeyValue{
					StrTag("span.kind", "client"),
					StrTag("phase", "verification"),
					StrTag("verifier.type", "committee-verifier"),
					StrTag("verifier.node_id", "nop-1"),
					StrTag("ccip.message_id", MessageID),
					StrTag("source_chain.fetch.status", "success"),
					StrTag("verification.checks.status", "success"),
					StrTag("signature.status", "signed"),
					StrTag("aggregator.push.status", "success"),
					BoolTag("verification.contributed_to_quorum", true),
					BoolTag("error", false),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0+Millis(4050), []KeyValue{
						StrTag("event", "committee_verifier.started"),
						StrTag("node_id", "nop-1"),
					}),
					SpanLogEntry(t0+Millis(4300), []KeyValue{
						StrTag("event", "source_chain.data_fetched"),
						StrTag("node_id", "nop-1"),
						StrTag("source_chain_selector", msg.SourceChainSelector),
					}),
					SpanLogEntry(t0+Millis(4700), []KeyValue{
						StrTag("event", "message.checked"),
						StrTag("node_id", "nop-1"),
						StrTag("checks.status", "success"),
					}),
					SpanLogEntry(t0+Millis(4850), []KeyValue{
						StrTag("event", "message.signed"),
						StrTag("node_id", "nop-1"),
						StrTag("signature", "0xnop1_signature_mock"),
					}),
					SpanLogEntry(t0+Millis(5250), []KeyValue{
						StrTag("event", "aggregator.pushed"),
						StrTag("node_id", "nop-1"),
						StrTag("push.status", "accepted"),
					}),
				},
			},
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000012",
				OperationName: "committee-verifier.verify/nop-2",
				References:    ChildOf("0000000000000003"),
				StartTime:     t0 + Millis(4100),
				Duration:      Millis(1600),
				ProcessID:     "p3",
				Tags: []KeyValue{
					StrTag("span.kind", "client"),
					StrTag("phase", "verification"),
					StrTag("verifier.type", "committee-verifier"),
					StrTag("verifier.node_id", "nop-2"),
					StrTag("ccip.message_id", MessageID),
					StrTag("source_chain.fetch.status", "success"),
					StrTag("verification.checks.status", "success"),
					StrTag("signature.status", "signed"),
					StrTag("aggregator.push.status", "success"),
					BoolTag("verification.contributed_to_quorum", true),
					BoolTag("error", false),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0+Millis(4100), []KeyValue{
						StrTag("event", "committee_verifier.started"),
						StrTag("node_id", "nop-2"),
					}),
					SpanLogEntry(t0+Millis(4600), []KeyValue{
						StrTag("event", "source_chain.data_fetched"),
						StrTag("node_id", "nop-2"),
						StrTag("source_chain_selector", msg.SourceChainSelector),
					}),
					SpanLogEntry(t0+Millis(5100), []KeyValue{
						StrTag("event", "message.checked"),
						StrTag("node_id", "nop-2"),
						StrTag("checks.status", "success"),
					}),
					SpanLogEntry(t0+Millis(5300), []KeyValue{
						StrTag("event", "message.signed"),
						StrTag("node_id", "nop-2"),
						StrTag("signature", "0xnop2_signature_mock"),
					}),
					SpanLogEntry(t0+Millis(5700), []KeyValue{
						StrTag("event", "aggregator.pushed"),
						StrTag("node_id", "nop-2"),
						StrTag("push.status", "accepted"),
					}),
				},
			},
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000013",
				OperationName: "committee-verifier.verify/nop-3",
				References:    ChildOf("0000000000000003"),
				StartTime:     t0 + Millis(4250),
				Duration:      Millis(1850),
				ProcessID:     "p3",
				Tags: []KeyValue{
					StrTag("span.kind", "client"),
					StrTag("phase", "verification"),
					StrTag("verifier.type", "committee-verifier"),
					StrTag("verifier.node_id", "nop-3"),
					StrTag("ccip.message_id", MessageID),
					StrTag("source_chain.fetch.status", "success"),
					StrTag("verification.checks.status", "success"),
					StrTag("signature.status", "signed"),
					StrTag("aggregator.push.status", "success"),
					BoolTag("verification.quorum_trigger", true),
					BoolTag("verification.contributed_to_quorum", true),
					BoolTag("error", false),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0+Millis(4250), []KeyValue{
						StrTag("event", "committee_verifier.started"),
						StrTag("node_id", "nop-3"),
					}),
					SpanLogEntry(t0+Millis(5000), []KeyValue{
						StrTag("event", "source_chain.data_fetched"),
						StrTag("node_id", "nop-3"),
						StrTag("source_chain_selector", msg.SourceChainSelector),
					}),
					SpanLogEntry(t0+Millis(5450), []KeyValue{
						StrTag("event", "message.checked"),
						StrTag("node_id", "nop-3"),
						StrTag("checks.status", "success"),
					}),
					SpanLogEntry(t0+Millis(5800), []KeyValue{
						StrTag("event", "message.signed"),
						StrTag("node_id", "nop-3"),
						StrTag("signature", "0xnop3_signature_mock"),
					}),
					SpanLogEntry(t0+Millis(6100), []KeyValue{
						StrTag("event", "aggregator.pushed"),
						StrTag("node_id", "nop-3"),
						StrTag("push.status", "accepted"),
					}),
					SpanLogEntry(t0+Millis(6100), []KeyValue{
						StrTag("event", "committee.quorum_reached"),
						StrTag("node_id", "nop-3"),
						IntTag("successful_submissions", 3),
						IntTag("required_submissions", 3),
					}),
				},
			},
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000014",
				OperationName: "committee-verifier.verify/nop-4",
				References:    ChildOf("0000000000000003"),
				StartTime:     t0 + Millis(4300),
				Duration:      Millis(4900),
				ProcessID:     "p3",
				Warnings: []string{
					"submitted error after committee quorum was already reached",
					"span ends after parent verification span",
				},
				Tags: []KeyValue{
					StrTag("span.kind", "client"),
					StrTag("phase", "verification"),
					StrTag("verifier.type", "committee-verifier"),
					StrTag("verifier.node_id", "nop-4"),
					StrTag("ccip.message_id", MessageID),
					StrTag("source_chain.fetch.status", "success"),
					StrTag("verification.checks.status", "failed"),
					StrTag("aggregator.push.status", "error"),
					BoolTag("verification.after_quorum", true),
					BoolTag("verification.contributed_to_quorum", false),
					BoolTag("error", true),
					StrTag("error.kind", "CommitteeVerifierError"),
					StrTag("error.message", "Invalid source-chain data proof"),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0+Millis(4300), []KeyValue{
						StrTag("event", "committee_verifier.started"),
						StrTag("node_id", "nop-4"),
					}),
					SpanLogEntry(t0+Millis(5400), []KeyValue{
						StrTag("event", "source_chain.data_fetched"),
						StrTag("node_id", "nop-4"),
						StrTag("source_chain_selector", msg.SourceChainSelector),
					}),
					SpanLogEntry(t0+Millis(8700), []KeyValue{
						StrTag("event", "verification.error"),
						StrTag("node_id", "nop-4"),
						StrTag("message", "Invalid source-chain data proof"),
					}),
					SpanLogEntry(t0+Millis(9200), []KeyValue{
						StrTag("event", "aggregator.pushed"),
						StrTag("node_id", "nop-4"),
						StrTag("push.status", "rejected"),
						StrTag("message", "Rejected after quorum had already been reached"),
					}),
				},
			},
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000015",
				OperationName: "committee-verifier.verify/nop-5",
				References:    ChildOf("0000000000000003"),
				StartTime:     t0 + Millis(4000),
				Duration:      Millis(2100),
				ProcessID:     "p3",
				Warnings: []string{
					"synthetic placeholder span for missing committee submission",
					"nop-5 did not submit anything",
				},
				Tags: []KeyValue{
					StrTag("span.kind", "client"),
					StrTag("phase", "verification"),
					StrTag("verifier.type", "committee-verifier"),
					StrTag("verifier.node_id", "nop-5"),
					StrTag("ccip.message_id", MessageID),
					StrTag("submission.status", "missing"),
					BoolTag("verification.contributed_to_quorum", false),
					BoolTag("error", true),
					StrTag("error.kind", "CommitteeVerifierMissingSubmission"),
					StrTag("error.message", "Committee verifier did not submit before verification completed"),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0+Millis(6100), []KeyValue{
						StrTag("event", "committee_verifier.missing_submission"),
						StrTag("node_id", "nop-5"),
						StrTag("message", "No submission observed before verification finished"),
					}),
				},
			},
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000021",
				OperationName: "token-verifier.usdc.verify/nop-tv",
				References:    ChildOf("0000000000000003"),
				StartTime:     t0 + Millis(4400),
				Duration:      Millis(3400),
				ProcessID:     "p5",
				Tags: []KeyValue{
					StrTag("span.kind", "client"),
					StrTag("phase", "verification"),
					StrTag("verifier.type", "token-verifier"),
					StrTag("verifier.node_id", "nop-tv"),
					StrTag("token.symbol", "USDC"),
					StrTag("ccip.message_id", MessageID),
					StrTag("source_chain.fetch.status", "success"),
					StrTag("usdc.api.poll.status", "success"),
					StrTag("storage.push.status", "success"),
					BoolTag("error", false),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0+Millis(4400), []KeyValue{
						StrTag("event", "token_verifier.started"),
						StrTag("node_id", "nop-tv"),
						StrTag("token", "USDC"),
					}),
					SpanLogEntry(t0+Millis(4700), []KeyValue{
						StrTag("event", "message.read"),
						StrTag("node_id", "nop-tv"),
						StrTag("message_id", MessageID),
					}),
					SpanLogEntry(t0+Millis(5400), []KeyValue{
						StrTag("event", "source_chain.data_fetched"),
						StrTag("node_id", "nop-tv"),
						StrTag("source_chain_selector", msg.SourceChainSelector),
					}),
					SpanLogEntry(t0+Millis(6200), []KeyValue{
						StrTag("event", "usdc.api.poll.started"),
						StrTag("node_id", "nop-tv"),
					}),
					SpanLogEntry(t0+Millis(7600), []KeyValue{
						StrTag("event", "usdc.api.poll.completed"),
						StrTag("node_id", "nop-tv"),
						StrTag("usdc.status", "confirmed"),
					}),
					SpanLogEntry(t0+Millis(7700), []KeyValue{
						StrTag("event", "token_verifier.pushing_to_storage"),
						StrTag("node_id", "nop-tv"),
						StrTag("message", "Pushing USDC attestation result to token verifier storage"),
					}),
					SpanLogEntry(t0+Millis(7800), []KeyValue{
						StrTag("event", "token_verifier.pushed_to_storage"),
						StrTag("node_id", "nop-tv"),
						StrTag("message", "USDC attestation result stored"),
					}),
				},
			},
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000022",
				OperationName: "aggregator.collect",
				References:    ChildOf("0000000000000003"),
				StartTime:     t0 + Millis(4000),
				Duration:      Millis(2100),
				ProcessID:     "p6",
				Tags: []KeyValue{
					StrTag("span.kind", "server"),
					StrTag("phase", "verification"),
					StrTag("ccip.message_id", MessageID),
					IntTag("aggregator.quorum.required", 3),
					IntTag("aggregator.submissions.received", 3),
					StrTag("aggregator.quorum.status", "reached"),
					BoolTag("error", false),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0+Millis(4000), []KeyValue{
						StrTag("event", "aggregator.started"),
						StrTag("message", "Aggregator listening for committee submissions"),
					}),
					SpanLogEntry(t0+Millis(5250), []KeyValue{
						StrTag("event", "aggregator.submission_received"),
						StrTag("node_id", "nop-1"),
						IntTag("submissions_so_far", 1),
					}),
					SpanLogEntry(t0+Millis(5700), []KeyValue{
						StrTag("event", "aggregator.submission_received"),
						StrTag("node_id", "nop-2"),
						IntTag("submissions_so_far", 2),
					}),
					SpanLogEntry(t0+Millis(6100), []KeyValue{
						StrTag("event", "aggregator.submission_received"),
						StrTag("node_id", "nop-3"),
						IntTag("submissions_so_far", 3),
					}),
					SpanLogEntry(t0+Millis(6100), []KeyValue{
						StrTag("event", "aggregator.quorum_reached"),
						StrTag("message", "Quorum reached; building merkle root report"),
						IntTag("successful_submissions", 3),
						IntTag("required_submissions", 3),
					}),
					SpanLogEntry(t0+Millis(6100), []KeyValue{
						StrTag("event", "aggregator.report_pushed"),
						StrTag("message", "Merkle root report pushed on-chain"),
					}),
				},
			},
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000041",
				OperationName: "indexer.poll_aggregator",
				References:    ChildOf("0000000000000001"),
				StartTime:     t0 + Millis(6000),
				Duration:      Millis(300),
				ProcessID:     "p7",
				Tags: []KeyValue{
					StrTag("span.kind", "client"),
					StrTag("phase", "indexing"),
					StrTag("ccip.message_id", MessageID),
					StrTag("poll.target", "aggregator"),
					StrTag("poll.result", "report_found"),
					BoolTag("error", false),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0+Millis(6000), []KeyValue{
						StrTag("event", "indexer.poll_started"),
						StrTag("target", "aggregator"),
					}),
					SpanLogEntry(t0+Millis(6300), []KeyValue{
						StrTag("event", "indexer.report_discovered"),
						StrTag("target", "aggregator"),
						StrTag("message", "Aggregator merkle root report found in DB"),
					}),
				},
			},
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000042",
				OperationName: "indexer.poll_token_verifier",
				References:    ChildOf("0000000000000001"),
				StartTime:     t0 + Millis(7100),
				Duration:      Millis(900),
				ProcessID:     "p7",
				Tags: []KeyValue{
					StrTag("span.kind", "client"),
					StrTag("phase", "indexing"),
					StrTag("ccip.message_id", MessageID),
					StrTag("poll.target", "token-verifier"),
					StrTag("poll.result", "result_found"),
					BoolTag("error", false),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0+Millis(7100), []KeyValue{
						StrTag("event", "indexer.poll_started"),
						StrTag("target", "token-verifier"),
					}),
					SpanLogEntry(t0+Millis(8000), []KeyValue{
						StrTag("event", "indexer.result_discovered"),
						StrTag("target", "token-verifier"),
						StrTag("message", "Token verifier USDC attestation result found in storage"),
					}),
				},
			},
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000043",
				OperationName: "indexer.ingest",
				References:    ChildOf("0000000000000001"),
				StartTime:     t0 + Millis(6000),
				Duration:      Millis(2000),
				ProcessID:     "p7",
				Tags: []KeyValue{
					StrTag("span.kind", "internal"),
					StrTag("phase", "indexing"),
					StrTag("ccip.message_id", MessageID),
					StrTag("ingest.status", "complete"),
					BoolTag("error", false),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0+Millis(6000), []KeyValue{
						StrTag("event", "ingest.started"),
						StrTag("message", "Ingestion started; polling aggregator and token verifier"),
					}),
					SpanLogEntry(t0+Millis(6300), []KeyValue{
						StrTag("event", "ingest.aggregator_report_received"),
						StrTag("message", "Aggregator merkle root report ingested"),
					}),
					SpanLogEntry(t0+Millis(8000), []KeyValue{
						StrTag("event", "ingest.completed"),
						StrTag("message", "Token verifier result ingested; signalling execution"),
					}),
				},
			},
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000004",
				OperationName: "ccip.execution",
				References:    ChildOf("0000000000000001"),
				StartTime:     t0 + Millis(8000),
				Duration:      Millis(5100),
				ProcessID:     "p4",
				Warnings: []string{
					"executor-1 failed with AlreadyExecuted after executor-2 succeeded",
					"executor-1 span ends after parent execution span",
				},
				Tags: []KeyValue{
					StrTag("span.kind", "consumer"),
					StrTag("phase", "execution"),
					StrTag("ccip.message_id", MessageID),
					IntTag("ccip.message_number", stateChanged.MessageNumber),
					StrTag("execution.status", "success"),
					StrTag("execution.successful_executor", "executor-2"),
					StrTag("execution.failed_executor", "executor-1"),
					BoolTag("error", false),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0+Millis(8000), []KeyValue{
						StrTag("event", "execution.started"),
						StrTag("message", "Execution started after indexer ingestion completed"),
					}),
					SpanLogEntry(t0+Millis(13000), []KeyValue{
						StrTag("event", "executor_2.started"),
						StrTag("executor", "executor-2"),
						StrTag("message", "Protocol delay elapsed; second executor started"),
					}),
					SpanLogEntry(t0+Millis(13100), []KeyValue{
						StrTag("event", "ExecutionStateChanged"),
						StrTag("payload", MustJSONString(stateChanged)),
					}),
					SpanLogEntry(t0+Millis(13100), []KeyValue{
						StrTag("event", "execution.completed"),
						StrTag("message", "Execution completed; executor-2 succeeded"),
					}),
				},
			},
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000031",
				OperationName: "executor.execute",
				References:    ChildOf("0000000000000004"),
				StartTime:     t0 + Millis(8000),
				Duration:      Seconds(7),
				ProcessID:     "p4",
				Warnings: []string{
					"executor lost race; message was already executed by executor-2",
				},
				Tags: []KeyValue{
					StrTag("span.kind", "client"),
					StrTag("phase", "execution"),
					StrTag("executor.id", "executor-1"),
					StrTag("ccip.message_id", MessageID),
					StrTag("execution.result", "AlreadyExecuted"),
					BoolTag("error", true),
					StrTag("error.kind", "AlreadyExecuted"),
					StrTag("error.message", "Message was already executed by another executor"),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0+Millis(8000), []KeyValue{
						StrTag("event", "executor.started"),
						StrTag("executor", "executor-1"),
					}),
					SpanLogEntry(t0+Millis(10900), []KeyValue{
						StrTag("event", "destination_chain.tx_submitted"),
						StrTag("executor", "executor-1"),
						StrTag("tx_hash", "0xexecutor1_mock_tx"),
					}),
					SpanLogEntry(t0+Millis(15000), []KeyValue{
						StrTag("event", "executor.failed"),
						StrTag("executor", "executor-1"),
						StrTag("error", "AlreadyExecuted"),
						StrTag("message", "Message was already executed by executor-2"),
					}),
				},
			},
			{
				TraceID:       MessageID,
				SpanID:        "0000000000000032",
				OperationName: "executor.execute",
				References:    ChildOf("0000000000000004"),
				StartTime:     t0 + Millis(13000),
				Duration:      Millis(100),
				ProcessID:     "p4",
				Tags: []KeyValue{
					StrTag("span.kind", "client"),
					StrTag("phase", "execution"),
					StrTag("executor.id", "executor-2"),
					StrTag("ccip.message_id", MessageID),
					StrTag("execution.result", "success"),
					IntTag("ccip.execution_state", stateChanged.State),
					StrTag("ccip.return_data", stateChanged.ReturnData),
					BoolTag("error", false),
				},
				Logs: []SpanLog{
					SpanLogEntry(t0+Millis(13000), []KeyValue{
						StrTag("event", "executor.started"),
						StrTag("executor", "executor-2"),
						StrTag("message", "Executor started after protocol delay"),
					}),
					SpanLogEntry(t0+Millis(13050), []KeyValue{
						StrTag("event", "destination_chain.tx_submitted"),
						StrTag("executor", "executor-2"),
						StrTag("tx_hash", "0xexecutor2_mock_tx"),
					}),
					SpanLogEntry(t0+Millis(13100), []KeyValue{
						StrTag("event", "executor.succeeded"),
						StrTag("executor", "executor-2"),
						StrTag("message", "Message executed successfully"),
					}),
					SpanLogEntry(t0+Millis(13100), []KeyValue{
						StrTag("event", "ExecutionStateChanged"),
						StrTag("payload", MustJSONString(stateChanged)),
					}),
				},
			},
		},
		Processes: map[string]Process{
			"p1": {
				ServiceName: "ccip2.0",
				Tags: []KeyValue{
					StrTag("component", "ccip-lifecycle-coordinator"),
					StrTag("deployment.environment", "local"),
				},
			},
			"p2": {
				ServiceName: "ethereum-testnet",
				Tags: []KeyValue{
					StrTag("component", "source-chain-finalizer"),
					StrTag("chain.selector", msg.SourceChainSelector),
				},
			},
			"p3": {
				ServiceName: "committee-verifier",
				Tags: []KeyValue{
					StrTag("component", "committee-verifier"),
					StrTag("committee.nodes", "nop-1,nop-2,nop-3,nop-4,nop-5"),
				},
			},
			"p5": {
				ServiceName: "token-verifier",
				Tags: []KeyValue{
					StrTag("component", "token-verifier"),
					StrTag("node.id", "nop-tv"),
				},
			},
			"p6": {
				ServiceName: "aggregator",
				Tags: []KeyValue{
					StrTag("component", "committee-aggregator"),
				},
			},
			"p7": {
				ServiceName: "indexer",
				Tags: []KeyValue{
					StrTag("component", "message-indexer"),
				},
			},
			"p4": {
				ServiceName: "base-testnet",
				Tags: []KeyValue{
					StrTag("component", "destination-executor"),
					StrTag("executors", "executor-1,executor-2"),
					StrTag("chain.selector", msg.DestChainSelector),
				},
			},
		},
		Warnings: nil,
	}
}

func CCIPMessageSentData() CCIPMessageSent {
	return CCIPMessageSent{
		Data:     nil,
		Sender:   "0x4b431813bcf797bf9bf93890656618ac80a1d5d2",
		Version:  1,
		DestBlob: nil,
		FeeToken: "0x1cd0690ff9a693f5ef2dd976660a8dafc81a109c",
		Receipts: []Receipt{
			{
				Issuer:            "0x2caafd3b4cf606220580c885bd2b448fb93dc03b",
				ExtraArgs:         "0x",
				DestGasLimit:      75000,
				FeeTokenAmount:    "0",
				DestBytesOverhead: 582,
			},
			{
				Issuer:            "0x6608d995bbde874de5292bfd289643c88d176ed3",
				ExtraArgs:         "0x",
				DestGasLimit:      200000,
				FeeTokenAmount:    "10003901521593420",
				DestBytesOverhead: 183,
			},
			{
				Issuer:            "0x0aa145a62153190b8f0d3ca00c441e451529f755",
				ExtraArgs:         "0x",
				DestGasLimit:      0,
				FeeTokenAmount:    "100039015215934200",
				DestBytesOverhead: 0,
			},
		},
		Receiver:       "0x4b431813bcf797bf9bf93890656618ac80a1d5d2",
		MessageID:      MessageID,
		TokenAmounts:   []any{},
		FinalityDepth:  0,
		OnRampAddress:  "0x0c26ecdac3637d5833cc53663f571df242d36cf5",
		EncodedMessage: "0x013d6d8f0fa1b00cccf8946d7c5b972a83000000000000001000072c3b000000000000000057f26601394e874c981211a7626034b7130cd6a1b5c61d89ff5e9d15118a7ae3200000000000000000000000000c26ecdac3637d5833cc53663f571df242d36cf514102423a5371944ab99aad7185052f969904c6d65200000000000000000000000004b431813bcf797bf9bf93890656618ac80a1d5d2144b431813bcf797bf9bf93890656618ac80a1d5d2000000000000",
		OffRampAddress: "0x102423a5371944ab99aad7185052f969904c6d65",
		SequenceNumber: 16,

		// These exceed JavaScript's safe integer range, so keep them as strings in JSON.
		DestChainSelector:   "17912061998839310000",
		SourceChainSelector: "4426351306075016000",

		ExecutionGasLimit:   470075,
		CCVAndExecutorHash:  "0x57f26601394e874c981211a7626034b7130cd6a1b5c61d89ff5e9d15118a7ae3",
		CCIPReceiveGasLimit: 0,
	}
}

func ExecutionStateChangedData() ExecutionStateChanged {
	return ExecutionStateChanged{
		State:               2,
		MessageID:           MessageID,
		ReturnData:          "0x",
		MessageNumber:       16,
		SourceChainSelector: "4426351306075016000",
	}
}

func ChildOf(parentSpanID string) []Reference {
	return []Reference{
		{
			RefType: "CHILD_OF",
			TraceID: MessageID,
			SpanID:  parentSpanID,
		},
	}
}

func SpanLogEntry(timestamp int64, fields []KeyValue) SpanLog {
	return SpanLog{
		Timestamp: timestamp,
		Fields:    fields,
	}
}

func StrTag(key, value string) KeyValue {
	return KeyValue{Key: key, Type: "string", Value: value}
}

func IntTag(key string, value int) KeyValue {
	return KeyValue{Key: key, Type: "int64", Value: value}
}

func BoolTag(key string, value bool) KeyValue {
	return KeyValue{Key: key, Type: "bool", Value: value}
}

func MustJSONString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func MustMicros(ts string) int64 {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		panic(err)
	}
	return t.UnixMicro()
}

func Seconds(n int64) int64 {
	return n * int64(time.Second/time.Microsecond)
}

func Millis(n int64) int64 {
	return n * int64(time.Millisecond/time.Microsecond)
}
