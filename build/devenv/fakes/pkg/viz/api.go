package viz

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/fake"
)

const (
	messageID = "0x1fedb7ff3a17716f4f3beb2c8e2f3558a76fba88f69fc5f9de5578f5f434a1f2"
)

type JaegerAPI struct{}

func NewJaegerAPI() *JaegerAPI {
	return &JaegerAPI{}
}

// Register registers the mock Jaeger Query API endpoints with the fake service.
func (j *JaegerAPI) Register() error {
	err := fake.Func("GET", "/viz/api/traces/:traceID", func(ctx *gin.Context) {
		requestedTraceID := ctx.Param("traceID")

		if requestedTraceID != messageID {
			ctx.JSON(http.StatusNotFound, JaegerResponse{
				Data:   []Trace{},
				Total:  0,
				Limit:  0,
				Offset: 0,
				Errors: []map[string]any{
					{
						"code": 404,
						"msg":  "trace not found",
					},
				},
			})
			return
		}

		ctx.JSON(http.StatusOK, JaegerResponse{
			Data:   []Trace{buildTrace()},
			Total:  1,
			Limit:  0,
			Offset: 0,
			Errors: nil,
		})
	})
	if err != nil {
		return err
	}

	err = fake.Func("GET", "/viz/api/services", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"data": []string{
				"ccip2.0",
				"ethereum-testnet",
				"committee-verifier",
				"token-verifier",
				"aggregator",
				"indexer",
				"base-testnet",
			},
			"total":  7,
			"limit":  0,
			"offset": 0,
			"errors": nil,
		})
	})
	if err != nil {
		return err
	}

	err = fake.Func("GET", "/viz/api/services/:service/operations", func(ctx *gin.Context) {
		operationsByService := map[string][]string{
			"ccip2.0": {
				"ccip.message",
				"ccip.verification",
			},
			"ethereum-testnet": {
				"ccip.finalization",
			},
			"committee-verifier": {
				"committee-verifier.verify/nop-1",
				"committee-verifier.verify/nop-2",
				"committee-verifier.verify/nop-3",
				"committee-verifier.verify/nop-4",
				"committee-verifier.verify/nop-5",
			},
			"token-verifier": {
				"token-verifier.usdc.verify/nop-tv",
			},
			"aggregator": {
				"aggregator.collect",
			},
			"indexer": {
				"indexer.poll_aggregator",
				"indexer.poll_token_verifier",
				"indexer.ingest",
			},
			"base-testnet": {
				"ccip.execution",
				"executor.execute",
			},
		}

		operations := operationsByService[ctx.Param("service")]

		ctx.JSON(http.StatusOK, gin.H{
			"data":   operations,
			"total":  len(operations),
			"limit":  0,
			"offset": 0,
			"errors": nil,
		})
	})
	if err != nil {
		return err
	}

	return nil
}

type JaegerResponse struct {
	Data   []Trace `json:"data"`
	Total  int     `json:"total"`
	Limit  int     `json:"limit"`
	Offset int     `json:"offset"`
	Errors any     `json:"errors"`
}

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

func buildTrace() Trace {
	t0 := mustMicros("2026-06-01T15:48:29Z")

	msg := ccipMessageSent()
	stateChanged := executionStateChanged()

	return Trace{
		TraceID: messageID,
		Spans: []Span{
			{
				TraceID:       messageID,
				SpanID:        "0000000000000001",
				OperationName: "ccip.message",
				References:    []Reference{},
				StartTime:     t0,
				Duration:      millis(13100),
				ProcessID:     "p1",
				Warnings: []string{
					"mock trace",
					"hardcoded CCIP trace",
					"contains synthetic warnings and errors for UI/testing",
					"committee-verifier/nop-4 span ends after its parent verification span",
					"executor-1 span ends after parent execution span",
				},
				Tags: []KeyValue{
					strTag("span.kind", "server"),
					strTag("service.version", "mock-ccip-jaeger-v1"),
					strTag("ccip.message_id", messageID),
					intTag("ccip.sequence_number", msg.SequenceNumber),
					strTag("ccip.source_chain_selector", msg.SourceChainSelector),
					strTag("ccip.dest_chain_selector", msg.DestChainSelector),
					strTag("ccip.sender", msg.Sender),
					strTag("ccip.receiver", msg.Receiver),
					strTag("ccip.on_ramp", msg.OnRampAddress),
					strTag("ccip.off_ramp", msg.OffRampAddress),
					strTag("ccip.fee_token", msg.FeeToken),
					intTag("ccip.receipts_count", len(msg.Receipts)),
					intTag("ccip.execution_gas_limit", msg.ExecutionGasLimit),
					boolTag("error", false),
				},
				Logs: []SpanLog{
					spanLog(t0, []KeyValue{
						strTag("event", "trace.started"),
						strTag("message", "CCIP message lifecycle started"),
					}),
					spanLog(t0, []KeyValue{
						strTag("event", "CCIPMessageSent"),
						strTag("payload", mustJSONString(msg)),
					}),
					spanLog(t0+millis(13100), []KeyValue{
						strTag("event", "trace.completed"),
						strTag("message", "CCIP message lifecycle completed"),
					}),
				},
			},
			{
				TraceID:       messageID,
				SpanID:        "0000000000000002",
				OperationName: "ccip.finalization",
				References:    childOf("0000000000000001"),
				StartTime:     t0,
				Duration:      seconds(4),
				ProcessID:     "p2",
				Warnings: []string{
					"finalityDepth is 0; finalization span is synthetic",
				},
				Tags: []KeyValue{
					strTag("span.kind", "internal"),
					strTag("phase", "finalization"),
					strTag("ccip.message_id", messageID),
					intTag("ccip.finality_depth", msg.FinalityDepth),
					strTag("blockchain.source_chain_selector", msg.SourceChainSelector),
					boolTag("error", false),
				},
				Logs: []SpanLog{
					spanLog(t0, []KeyValue{
						strTag("event", "finalization.started"),
						strTag("message", "Waiting for source-chain finality"),
					}),
					spanLog(t0+seconds(1), []KeyValue{
						strTag("event", "context"),
						strTag("source_chain_selector", msg.SourceChainSelector),
						intTag("sequence_number", msg.SequenceNumber),
						intTag("finality_depth", msg.FinalityDepth),
					}),
					spanLog(t0+seconds(4), []KeyValue{
						strTag("event", "finalization.completed"),
						strTag("message", "Message considered finalized for mock trace"),
					}),
				},
			},
			{
				TraceID:       messageID,
				SpanID:        "0000000000000003",
				OperationName: "ccip.verification",
				References:    childOf("0000000000000001"),
				StartTime:     t0 + seconds(4),
				Duration:      millis(3800),
				ProcessID:     "p1",
				Warnings: []string{
					"committee-verifier/nop-5 did not submit",
					"committee-verifier/nop-4 submitted an error after quorum was reached",
					"child span committee-verifier/nop-4 ends after parent verification span",
				},
				Tags: []KeyValue{
					strTag("span.kind", "internal"),
					strTag("phase", "verification"),
					strTag("ccip.message_id", messageID),
					strTag("verification.status", "success"),
					strTag("verification.quorum.status", "reached"),
					intTag("verification.quorum.required", 3),
					intTag("verification.committee.total", 5),
					intTag("verification.committee.successful", 3),
					intTag("verification.committee.failed", 1),
					intTag("verification.committee.missing", 1),
					strTag("verification.quorum_reached_by", "nop-1,nop-2,nop-3"),
					strTag("verification.missing_nops", "nop-5"),
					boolTag("error", false),
				},
				Logs: []SpanLog{
					spanLog(t0+seconds(4), []KeyValue{
						strTag("event", "verification.started"),
						strTag("message", "Starting message verification"),
					}),
					spanLog(t0+millis(6100), []KeyValue{
						strTag("event", "committee.quorum_reached"),
						strTag("message", "Committee quorum reached after 3 successful submissions"),
						intTag("successful_submissions", 3),
						intTag("required_submissions", 3),
						strTag("nodes", "nop-1,nop-2,nop-3"),
					}),
					spanLog(t0+millis(6100), []KeyValue{
						strTag("event", "aggregator.report_pushed"),
						strTag("message", "Aggregator pushed merkle root report after quorum"),
					}),
					spanLog(t0+millis(7800), []KeyValue{
						strTag("event", "verification.completed"),
						strTag("message", "Verification completed; token verifier pushed result to storage"),
					}),
				},
			},
			{
				TraceID:       messageID,
				SpanID:        "0000000000000011",
				OperationName: "committee-verifier.verify/nop-1",
				References:    childOf("0000000000000003"),
				StartTime:     t0 + millis(4050),
				Duration:      millis(1200),
				ProcessID:     "p3",
				Tags: []KeyValue{
					strTag("span.kind", "client"),
					strTag("phase", "verification"),
					strTag("verifier.type", "committee-verifier"),
					strTag("verifier.node_id", "nop-1"),
					strTag("ccip.message_id", messageID),
					strTag("source_chain.fetch.status", "success"),
					strTag("verification.checks.status", "success"),
					strTag("signature.status", "signed"),
					strTag("aggregator.push.status", "success"),
					boolTag("verification.contributed_to_quorum", true),
					boolTag("error", false),
				},
				Logs: []SpanLog{
					spanLog(t0+millis(4050), []KeyValue{
						strTag("event", "committee_verifier.started"),
						strTag("node_id", "nop-1"),
					}),
					spanLog(t0+millis(4300), []KeyValue{
						strTag("event", "source_chain.data_fetched"),
						strTag("node_id", "nop-1"),
						strTag("source_chain_selector", msg.SourceChainSelector),
					}),
					spanLog(t0+millis(4700), []KeyValue{
						strTag("event", "message.checked"),
						strTag("node_id", "nop-1"),
						strTag("checks.status", "success"),
					}),
					spanLog(t0+millis(4850), []KeyValue{
						strTag("event", "message.signed"),
						strTag("node_id", "nop-1"),
						strTag("signature", "0xnop1_signature_mock"),
					}),
					spanLog(t0+millis(5250), []KeyValue{
						strTag("event", "aggregator.pushed"),
						strTag("node_id", "nop-1"),
						strTag("push.status", "accepted"),
					}),
				},
			},
			{
				TraceID:       messageID,
				SpanID:        "0000000000000012",
				OperationName: "committee-verifier.verify/nop-2",
				References:    childOf("0000000000000003"),
				StartTime:     t0 + millis(4100),
				Duration:      millis(1600),
				ProcessID:     "p3",
				Tags: []KeyValue{
					strTag("span.kind", "client"),
					strTag("phase", "verification"),
					strTag("verifier.type", "committee-verifier"),
					strTag("verifier.node_id", "nop-2"),
					strTag("ccip.message_id", messageID),
					strTag("source_chain.fetch.status", "success"),
					strTag("verification.checks.status", "success"),
					strTag("signature.status", "signed"),
					strTag("aggregator.push.status", "success"),
					boolTag("verification.contributed_to_quorum", true),
					boolTag("error", false),
				},
				Logs: []SpanLog{
					spanLog(t0+millis(4100), []KeyValue{
						strTag("event", "committee_verifier.started"),
						strTag("node_id", "nop-2"),
					}),
					spanLog(t0+millis(4600), []KeyValue{
						strTag("event", "source_chain.data_fetched"),
						strTag("node_id", "nop-2"),
						strTag("source_chain_selector", msg.SourceChainSelector),
					}),
					spanLog(t0+millis(5100), []KeyValue{
						strTag("event", "message.checked"),
						strTag("node_id", "nop-2"),
						strTag("checks.status", "success"),
					}),
					spanLog(t0+millis(5300), []KeyValue{
						strTag("event", "message.signed"),
						strTag("node_id", "nop-2"),
						strTag("signature", "0xnop2_signature_mock"),
					}),
					spanLog(t0+millis(5700), []KeyValue{
						strTag("event", "aggregator.pushed"),
						strTag("node_id", "nop-2"),
						strTag("push.status", "accepted"),
					}),
				},
			},
			{
				TraceID:       messageID,
				SpanID:        "0000000000000013",
				OperationName: "committee-verifier.verify/nop-3",
				References:    childOf("0000000000000003"),
				StartTime:     t0 + millis(4250),
				Duration:      millis(1850),
				ProcessID:     "p3",
				Tags: []KeyValue{
					strTag("span.kind", "client"),
					strTag("phase", "verification"),
					strTag("verifier.type", "committee-verifier"),
					strTag("verifier.node_id", "nop-3"),
					strTag("ccip.message_id", messageID),
					strTag("source_chain.fetch.status", "success"),
					strTag("verification.checks.status", "success"),
					strTag("signature.status", "signed"),
					strTag("aggregator.push.status", "success"),
					boolTag("verification.quorum_trigger", true),
					boolTag("verification.contributed_to_quorum", true),
					boolTag("error", false),
				},
				Logs: []SpanLog{
					spanLog(t0+millis(4250), []KeyValue{
						strTag("event", "committee_verifier.started"),
						strTag("node_id", "nop-3"),
					}),
					spanLog(t0+millis(5000), []KeyValue{
						strTag("event", "source_chain.data_fetched"),
						strTag("node_id", "nop-3"),
						strTag("source_chain_selector", msg.SourceChainSelector),
					}),
					spanLog(t0+millis(5450), []KeyValue{
						strTag("event", "message.checked"),
						strTag("node_id", "nop-3"),
						strTag("checks.status", "success"),
					}),
					spanLog(t0+millis(5800), []KeyValue{
						strTag("event", "message.signed"),
						strTag("node_id", "nop-3"),
						strTag("signature", "0xnop3_signature_mock"),
					}),
					spanLog(t0+millis(6100), []KeyValue{
						strTag("event", "aggregator.pushed"),
						strTag("node_id", "nop-3"),
						strTag("push.status", "accepted"),
					}),
					spanLog(t0+millis(6100), []KeyValue{
						strTag("event", "committee.quorum_reached"),
						strTag("node_id", "nop-3"),
						intTag("successful_submissions", 3),
						intTag("required_submissions", 3),
					}),
				},
			},
			{
				TraceID:       messageID,
				SpanID:        "0000000000000014",
				OperationName: "committee-verifier.verify/nop-4",
				References:    childOf("0000000000000003"),
				StartTime:     t0 + millis(4300),
				Duration:      millis(4900),
				ProcessID:     "p3",
				Warnings: []string{
					"submitted error after committee quorum was already reached",
					"span ends after parent verification span",
				},
				Tags: []KeyValue{
					strTag("span.kind", "client"),
					strTag("phase", "verification"),
					strTag("verifier.type", "committee-verifier"),
					strTag("verifier.node_id", "nop-4"),
					strTag("ccip.message_id", messageID),
					strTag("source_chain.fetch.status", "success"),
					strTag("verification.checks.status", "failed"),
					strTag("aggregator.push.status", "error"),
					boolTag("verification.after_quorum", true),
					boolTag("verification.contributed_to_quorum", false),
					boolTag("error", true),
					strTag("error.kind", "CommitteeVerifierError"),
					strTag("error.message", "Invalid source-chain data proof"),
				},
				Logs: []SpanLog{
					spanLog(t0+millis(4300), []KeyValue{
						strTag("event", "committee_verifier.started"),
						strTag("node_id", "nop-4"),
					}),
					spanLog(t0+millis(5400), []KeyValue{
						strTag("event", "source_chain.data_fetched"),
						strTag("node_id", "nop-4"),
						strTag("source_chain_selector", msg.SourceChainSelector),
					}),
					spanLog(t0+millis(8700), []KeyValue{
						strTag("event", "verification.error"),
						strTag("node_id", "nop-4"),
						strTag("message", "Invalid source-chain data proof"),
					}),
					spanLog(t0+millis(9200), []KeyValue{
						strTag("event", "aggregator.pushed"),
						strTag("node_id", "nop-4"),
						strTag("push.status", "rejected"),
						strTag("message", "Rejected after quorum had already been reached"),
					}),
				},
			},
			{
				TraceID:       messageID,
				SpanID:        "0000000000000015",
				OperationName: "committee-verifier.verify/nop-5",
				References:    childOf("0000000000000003"),
				StartTime:     t0 + millis(4000),
				Duration:      millis(2100),
				ProcessID:     "p3",
				Warnings: []string{
					"synthetic placeholder span for missing committee submission",
					"nop-5 did not submit anything",
				},
				Tags: []KeyValue{
					strTag("span.kind", "client"),
					strTag("phase", "verification"),
					strTag("verifier.type", "committee-verifier"),
					strTag("verifier.node_id", "nop-5"),
					strTag("ccip.message_id", messageID),
					strTag("submission.status", "missing"),
					boolTag("verification.contributed_to_quorum", false),
					boolTag("error", true),
					strTag("error.kind", "CommitteeVerifierMissingSubmission"),
					strTag("error.message", "Committee verifier did not submit before verification completed"),
				},
				Logs: []SpanLog{
					spanLog(t0+millis(6100), []KeyValue{
						strTag("event", "committee_verifier.missing_submission"),
						strTag("node_id", "nop-5"),
						strTag("message", "No submission observed before verification finished"),
					}),
				},
			},
			{
				TraceID:       messageID,
				SpanID:        "0000000000000021",
				OperationName: "token-verifier.usdc.verify/nop-tv",
				References:    childOf("0000000000000003"),
				StartTime:     t0 + millis(4400),
				Duration:      millis(3400),
				ProcessID:     "p5",
				Tags: []KeyValue{
					strTag("span.kind", "client"),
					strTag("phase", "verification"),
					strTag("verifier.type", "token-verifier"),
					strTag("verifier.node_id", "nop-tv"),
					strTag("token.symbol", "USDC"),
					strTag("ccip.message_id", messageID),
					strTag("source_chain.fetch.status", "success"),
					strTag("usdc.api.poll.status", "success"),
					strTag("storage.push.status", "success"),
					boolTag("error", false),
				},
				Logs: []SpanLog{
					spanLog(t0+millis(4400), []KeyValue{
						strTag("event", "token_verifier.started"),
						strTag("node_id", "nop-tv"),
						strTag("token", "USDC"),
					}),
					spanLog(t0+millis(4700), []KeyValue{
						strTag("event", "message.read"),
						strTag("node_id", "nop-tv"),
						strTag("message_id", messageID),
					}),
					spanLog(t0+millis(5400), []KeyValue{
						strTag("event", "source_chain.data_fetched"),
						strTag("node_id", "nop-tv"),
						strTag("source_chain_selector", msg.SourceChainSelector),
					}),
					spanLog(t0+millis(6200), []KeyValue{
						strTag("event", "usdc.api.poll.started"),
						strTag("node_id", "nop-tv"),
					}),
					spanLog(t0+millis(7600), []KeyValue{
						strTag("event", "usdc.api.poll.completed"),
						strTag("node_id", "nop-tv"),
						strTag("usdc.status", "confirmed"),
					}),
					spanLog(t0+millis(7700), []KeyValue{
						strTag("event", "token_verifier.pushing_to_storage"),
						strTag("node_id", "nop-tv"),
						strTag("message", "Pushing USDC attestation result to token verifier storage"),
					}),
					spanLog(t0+millis(7800), []KeyValue{
						strTag("event", "token_verifier.pushed_to_storage"),
						strTag("node_id", "nop-tv"),
						strTag("message", "USDC attestation result stored"),
					}),
				},
			},
			{
				TraceID:       messageID,
				SpanID:        "0000000000000022",
				OperationName: "aggregator.collect",
				References:    childOf("0000000000000003"),
				StartTime:     t0 + millis(4000),
				Duration:      millis(2100),
				ProcessID:     "p6",
				Tags: []KeyValue{
					strTag("span.kind", "server"),
					strTag("phase", "verification"),
					strTag("ccip.message_id", messageID),
					intTag("aggregator.quorum.required", 3),
					intTag("aggregator.submissions.received", 3),
					strTag("aggregator.quorum.status", "reached"),
					boolTag("error", false),
				},
				Logs: []SpanLog{
					spanLog(t0+millis(4000), []KeyValue{
						strTag("event", "aggregator.started"),
						strTag("message", "Aggregator listening for committee submissions"),
					}),
					spanLog(t0+millis(5250), []KeyValue{
						strTag("event", "aggregator.submission_received"),
						strTag("node_id", "nop-1"),
						intTag("submissions_so_far", 1),
					}),
					spanLog(t0+millis(5700), []KeyValue{
						strTag("event", "aggregator.submission_received"),
						strTag("node_id", "nop-2"),
						intTag("submissions_so_far", 2),
					}),
					spanLog(t0+millis(6100), []KeyValue{
						strTag("event", "aggregator.submission_received"),
						strTag("node_id", "nop-3"),
						intTag("submissions_so_far", 3),
					}),
					spanLog(t0+millis(6100), []KeyValue{
						strTag("event", "aggregator.quorum_reached"),
						strTag("message", "Quorum reached; building merkle root report"),
						intTag("successful_submissions", 3),
						intTag("required_submissions", 3),
					}),
					spanLog(t0+millis(6100), []KeyValue{
						strTag("event", "aggregator.report_pushed"),
						strTag("message", "Merkle root report pushed on-chain"),
					}),
				},
			},
			{
				TraceID:       messageID,
				SpanID:        "0000000000000041",
				OperationName: "indexer.poll_aggregator",
				References:    childOf("0000000000000001"),
				StartTime:     t0 + millis(6000),
				Duration:      millis(300),
				ProcessID:     "p7",
				Tags: []KeyValue{
					strTag("span.kind", "client"),
					strTag("phase", "indexing"),
					strTag("ccip.message_id", messageID),
					strTag("poll.target", "aggregator"),
					strTag("poll.result", "report_found"),
					boolTag("error", false),
				},
				Logs: []SpanLog{
					spanLog(t0+millis(6000), []KeyValue{
						strTag("event", "indexer.poll_started"),
						strTag("target", "aggregator"),
					}),
					spanLog(t0+millis(6300), []KeyValue{
						strTag("event", "indexer.report_discovered"),
						strTag("target", "aggregator"),
						strTag("message", "Aggregator merkle root report found in DB"),
					}),
				},
			},
			{
				TraceID:       messageID,
				SpanID:        "0000000000000042",
				OperationName: "indexer.poll_token_verifier",
				References:    childOf("0000000000000001"),
				StartTime:     t0 + millis(7100),
				Duration:      millis(900),
				ProcessID:     "p7",
				Tags: []KeyValue{
					strTag("span.kind", "client"),
					strTag("phase", "indexing"),
					strTag("ccip.message_id", messageID),
					strTag("poll.target", "token-verifier"),
					strTag("poll.result", "result_found"),
					boolTag("error", false),
				},
				Logs: []SpanLog{
					spanLog(t0+millis(7100), []KeyValue{
						strTag("event", "indexer.poll_started"),
						strTag("target", "token-verifier"),
					}),
					spanLog(t0+millis(8000), []KeyValue{
						strTag("event", "indexer.result_discovered"),
						strTag("target", "token-verifier"),
						strTag("message", "Token verifier USDC attestation result found in storage"),
					}),
				},
			},
			{
				TraceID:       messageID,
				SpanID:        "0000000000000043",
				OperationName: "indexer.ingest",
				References:    childOf("0000000000000001"),
				StartTime:     t0 + millis(6000),
				Duration:      millis(2000),
				ProcessID:     "p7",
				Tags: []KeyValue{
					strTag("span.kind", "internal"),
					strTag("phase", "indexing"),
					strTag("ccip.message_id", messageID),
					strTag("ingest.status", "complete"),
					boolTag("error", false),
				},
				Logs: []SpanLog{
					spanLog(t0+millis(6000), []KeyValue{
						strTag("event", "ingest.started"),
						strTag("message", "Ingestion started; polling aggregator and token verifier"),
					}),
					spanLog(t0+millis(6300), []KeyValue{
						strTag("event", "ingest.aggregator_report_received"),
						strTag("message", "Aggregator merkle root report ingested"),
					}),
					spanLog(t0+millis(8000), []KeyValue{
						strTag("event", "ingest.completed"),
						strTag("message", "Token verifier result ingested; signalling execution"),
					}),
				},
			},
			{
				TraceID:       messageID,
				SpanID:        "0000000000000004",
				OperationName: "ccip.execution",
				References:    childOf("0000000000000001"),
				StartTime:     t0 + millis(8000),
				Duration:      millis(5100),
				ProcessID:     "p4",
				Warnings: []string{
					"executor-1 failed with AlreadyExecuted after executor-2 succeeded",
					"executor-1 span ends after parent execution span",
				},
				Tags: []KeyValue{
					strTag("span.kind", "consumer"),
					strTag("phase", "execution"),
					strTag("ccip.message_id", messageID),
					intTag("ccip.message_number", stateChanged.MessageNumber),
					strTag("execution.status", "success"),
					strTag("execution.successful_executor", "executor-2"),
					strTag("execution.failed_executor", "executor-1"),
					boolTag("error", false),
				},
				Logs: []SpanLog{
					spanLog(t0+millis(8000), []KeyValue{
						strTag("event", "execution.started"),
						strTag("message", "Execution started after indexer ingestion completed"),
					}),
					spanLog(t0+millis(13000), []KeyValue{
						strTag("event", "executor_2.started"),
						strTag("executor", "executor-2"),
						strTag("message", "Protocol delay elapsed; second executor started"),
					}),
					spanLog(t0+millis(13100), []KeyValue{
						strTag("event", "ExecutionStateChanged"),
						strTag("payload", mustJSONString(stateChanged)),
					}),
					spanLog(t0+millis(13100), []KeyValue{
						strTag("event", "execution.completed"),
						strTag("message", "Execution completed; executor-2 succeeded"),
					}),
				},
			},
			{
				TraceID:       messageID,
				SpanID:        "0000000000000031",
				OperationName: "executor.execute",
				References:    childOf("0000000000000004"),
				StartTime:     t0 + millis(8000),
				Duration:      seconds(7),
				ProcessID:     "p4",
				Warnings: []string{
					"executor lost race; message was already executed by executor-2",
				},
				Tags: []KeyValue{
					strTag("span.kind", "client"),
					strTag("phase", "execution"),
					strTag("executor.id", "executor-1"),
					strTag("ccip.message_id", messageID),
					strTag("execution.result", "AlreadyExecuted"),
					boolTag("error", true),
					strTag("error.kind", "AlreadyExecuted"),
					strTag("error.message", "Message was already executed by another executor"),
				},
				Logs: []SpanLog{
					spanLog(t0+millis(8000), []KeyValue{
						strTag("event", "executor.started"),
						strTag("executor", "executor-1"),
					}),
					spanLog(t0+millis(10900), []KeyValue{
						strTag("event", "destination_chain.tx_submitted"),
						strTag("executor", "executor-1"),
						strTag("tx_hash", "0xexecutor1_mock_tx"),
					}),
					spanLog(t0+millis(15000), []KeyValue{
						strTag("event", "executor.failed"),
						strTag("executor", "executor-1"),
						strTag("error", "AlreadyExecuted"),
						strTag("message", "Message was already executed by executor-2"),
					}),
				},
			},
			{
				TraceID:       messageID,
				SpanID:        "0000000000000032",
				OperationName: "executor.execute",
				References:    childOf("0000000000000004"),
				StartTime:     t0 + millis(13000),
				Duration:      millis(100),
				ProcessID:     "p4",
				Tags: []KeyValue{
					strTag("span.kind", "client"),
					strTag("phase", "execution"),
					strTag("executor.id", "executor-2"),
					strTag("ccip.message_id", messageID),
					strTag("execution.result", "success"),
					intTag("ccip.execution_state", stateChanged.State),
					strTag("ccip.return_data", stateChanged.ReturnData),
					boolTag("error", false),
				},
				Logs: []SpanLog{
					spanLog(t0+millis(13000), []KeyValue{
						strTag("event", "executor.started"),
						strTag("executor", "executor-2"),
						strTag("message", "Executor started after protocol delay"),
					}),
					spanLog(t0+millis(13050), []KeyValue{
						strTag("event", "destination_chain.tx_submitted"),
						strTag("executor", "executor-2"),
						strTag("tx_hash", "0xexecutor2_mock_tx"),
					}),
					spanLog(t0+millis(13100), []KeyValue{
						strTag("event", "executor.succeeded"),
						strTag("executor", "executor-2"),
						strTag("message", "Message executed successfully"),
					}),
					spanLog(t0+millis(13100), []KeyValue{
						strTag("event", "ExecutionStateChanged"),
						strTag("payload", mustJSONString(stateChanged)),
					}),
				},
			},
		},
		Processes: map[string]Process{
			"p1": {
				ServiceName: "ccip2.0",
				Tags: []KeyValue{
					strTag("component", "ccip-lifecycle-coordinator"),
					strTag("deployment.environment", "local"),
				},
			},
			"p2": {
				ServiceName: "ethereum-testnet",
				Tags: []KeyValue{
					strTag("component", "source-chain-finalizer"),
					strTag("chain.selector", msg.SourceChainSelector),
				},
			},
			"p3": {
				ServiceName: "committee-verifier",
				Tags: []KeyValue{
					strTag("component", "committee-verifier"),
					strTag("committee.nodes", "nop-1,nop-2,nop-3,nop-4,nop-5"),
				},
			},
			"p5": {
				ServiceName: "token-verifier",
				Tags: []KeyValue{
					strTag("component", "token-verifier"),
					strTag("node.id", "nop-tv"),
				},
			},
			"p6": {
				ServiceName: "aggregator",
				Tags: []KeyValue{
					strTag("component", "committee-aggregator"),
				},
			},
			"p7": {
				ServiceName: "indexer",
				Tags: []KeyValue{
					strTag("component", "message-indexer"),
				},
			},
			"p4": {
				ServiceName: "base-testnet",
				Tags: []KeyValue{
					strTag("component", "destination-executor"),
					strTag("executors", "executor-1,executor-2"),
					strTag("chain.selector", msg.DestChainSelector),
				},
			},
		},
		Warnings: nil,
	}
}

func ccipMessageSent() CCIPMessageSent {
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
		MessageID:      messageID,
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

func executionStateChanged() ExecutionStateChanged {
	return ExecutionStateChanged{
		State:               2,
		MessageID:           messageID,
		ReturnData:          "0x",
		MessageNumber:       16,
		SourceChainSelector: "4426351306075016000",
	}
}

func childOf(parentSpanID string) []Reference {
	return []Reference{
		{
			RefType: "CHILD_OF",
			TraceID: messageID,
			SpanID:  parentSpanID,
		},
	}
}

func spanLog(timestamp int64, fields []KeyValue) SpanLog {
	return SpanLog{
		Timestamp: timestamp,
		Fields:    fields,
	}
}

func strTag(key, value string) KeyValue {
	return KeyValue{
		Key:   key,
		Type:  "string",
		Value: value,
	}
}

func intTag(key string, value int) KeyValue {
	return KeyValue{
		Key:   key,
		Type:  "int64",
		Value: value,
	}
}

func boolTag(key string, value bool) KeyValue {
	return KeyValue{
		Key:   key,
		Type:  "bool",
		Value: value,
	}
}

func mustJSONString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}

	return string(b)
}

func mustMicros(ts string) int64 {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		panic(err)
	}

	return t.UnixMicro()
}

func seconds(n int64) int64 {
	return n * int64(time.Second/time.Microsecond)
}

func millis(n int64) int64 {
	return n * int64(time.Millisecond/time.Microsecond)
}
