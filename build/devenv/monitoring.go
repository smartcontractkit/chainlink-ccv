package ccv

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"go.uber.org/zap"

	ccvAggregator "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
	ccvProxy "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_proxy"
	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	LokiOnChainStreamURL = "http://localhost:3000/explore?panes=%7B%22UYG%22:%7B%22datasource%22:%22P8E80F9AEF21F6940%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22expr%22:%22%7Bjob%3D%5C%22on-chain%5C%22%7D%22,%22queryType%22:%22range%22,%22datasource%22:%7B%22type%22:%22loki%22,%22uid%22:%22P8E80F9AEF21F6940%22%7D,%22editorMode%22:%22code%22%7D%5D,%22range%22:%7B%22from%22:%22now-30m%22,%22to%22:%22now%22%7D%7D%7D&schemaVersion=1&orgId=1"
	PromMetrics          = "http://localhost:3000/explore?panes=%7B%22UYG%22:%7B%22datasource%22:%22PBFA97CFB590B2093%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22expr%22:%22on_chain_ccip_msg_sent_total%22,%22range%22:true,%22datasource%22:%7B%22type%22:%22prometheus%22,%22uid%22:%22PBFA97CFB590B2093%22%7D,%22editorMode%22:%22code%22,%22legendFormat%22:%22__auto%22%7D%5D,%22range%22:%7B%22from%22:%22now-30m%22,%22to%22:%22now%22%7D%7D%7D&schemaVersion=1&orgId=1"
)

var msgSentTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "on_chain_ccip_msg_sent_total",
	Help: "Total number of CCIP messages sent",
})

// srcDstLatency = promauto.NewHistogram(prometheus.HistogramOpts{
// 	Name:    "on_chain_src_dst_total_latency_milliseconds",
// 	Help:    "Total duration of processing message from src to dst chain",
// 	Buckets: prometheus.DefBuckets,
// }).

// MonitorOnChainLogs is converting specified on-chain events (logs) to Loki/Prometheus data
// it does not preserve original timestamps for observation and Loki pushes and scans/uploads the whole range
// in case we need to get realtime metrics this function can be converted to a service that calls this function with
// block ranges for both chains.
func MonitorOnChainLogs(in *Cfg) error {
	Plog.Info().Str("AggregatorAddress", in.Verifier.AggregatorAddress).Send()
	bcs, err := blockchainsByChainID(in)
	if err != nil {
		return err
	}
	lp := NewLokiPusher()
	tp := NewTempoPusher()
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	})

	storageReader, err := storageaccess.NewAggregatorReader("localhost:50051", lggr, 0)
	if err != nil {
		lggr.Errorw("Failed to create storage reader", "error", err)
	}
	ctx := context.Background()
	msgSentStreams, err := FilterContractEventsAllChains[ccvProxy.CCVProxyCCIPMessageSent](
		ctx,
		in,
		bcs,
		ccvProxy.CCVProxyMetaData.ABI,
		"CCVProxy",
		"CCIPMessageSent",
		nil,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to collect logs: %w", err)
	}
	msgExecStreams, err := FilterContractEventsAllChains[ccvAggregator.CCVAggregatorExecutionStateChanged](
		ctx,
		in,
		bcs,
		ccvAggregator.CCVAggregatorMetaData.ABI,
		"CCVAggregator",
		"ExecutionStateChanged",
		nil,
		nil,
	)
	ccv, err := storageReader.ReadCCVData(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect logs: %w", err)
	}
	// process Loki streams
	if err := lp.PushRawAndDecoded(msgSentStreams.RawLoki, msgSentStreams.DecodedLoki, "on-chain"); err != nil {
		return fmt.Errorf("failed to push logs: %w", err)
	}
	if err := lp.PushRawAndDecoded(msgExecStreams.RawLoki, msgExecStreams.DecodedLoki, "on-chain"); err != nil {
		return fmt.Errorf("failed to push logs: %w", err)
	}
	// process Prom metrics
	msgSentEvents := make(map[types.Bytes32]*DecodedLog[ccvProxy.CCVProxyCCIPMessageSent])
	msgSigEvents := make(map[types.Bytes32]types.CCVData)
	msgExecEvents := make(map[types.Bytes32]*DecodedLog[ccvAggregator.CCVAggregatorExecutionStateChanged])
	logTimeByMsgID := make(map[types.Bytes32]uint64)
	for _, l := range msgSentStreams.DecodedProm {
		if l.Name == "CCIPMessageSent" {
			if payload, ok := any(l.UnpackedData).(ccvProxy.CCVProxyCCIPMessageSent); ok {
				payload.DestChainSelector = binary.BigEndian.Uint64(l.Topics[1][24:]) // Last 8 bytes
				payload.SequenceNumber = binary.BigEndian.Uint64(l.Topics[2][24:])    // Last 8 bytes
				copy(payload.MessageId[:], l.Topics[3][:])                            // Full 32 bytes
				Plog.Info().
					Str("MsgID", fmt.Sprintf("%x", payload.MessageId)).
					Uint64("BlockTimestamp", l.BlockTimestamp).
					Msg("Received CCIPMessageSent log")
				msgSentTotal.Inc()
				logTimeByMsgID[payload.MessageId] = l.BlockTimestamp
				msgSentEvents[payload.MessageId] = l
			}
		}
	}
	for _, l := range msgExecStreams.DecodedProm {
		if l.Name == "ExecutionStateChanged" {
			if payload, ok := any(l.UnpackedData).(ccvAggregator.CCVAggregatorExecutionStateChanged); ok {
				payload.SourceChainSelector = binary.BigEndian.Uint64(l.Topics[1][24:]) // Last 8 bytes
				payload.SequenceNumber = binary.BigEndian.Uint64(l.Topics[2][24:])      // Last 8 bytes
				copy(payload.MessageId[:], l.Topics[3][:])                              // Full 32 bytes
				Plog.Info().
					Str("MsgID", fmt.Sprintf("%x", payload.MessageId)).
					Uint64("BlockTimestamp", l.BlockTimestamp).
					Msg("Received ExecutionStateChanged log")
				msgExecEvents[payload.MessageId] = l
				// TODO: get msgID and measure time for each variant of messages, no events emitted yet
				//srcDstLatency.Observe(float64(l.BlockTimestamp))
			}
		}
	}
	for _, l := range ccv {
		msgSigEvents[l.Data.MessageID] = l.Data
		Plog.Info().
			Str("MsgID", l.Data.MessageID.String()).
			Int64("Timestamp", l.Data.Timestamp).
			Msg("Received verifier signature")
	}
	for msgId, msgSent := range msgSentEvents {
		msgSig, okSig := msgSigEvents[msgId]
		msgExec, okExec := msgExecEvents[msgId]
		spans := make([]Span, 0, 2)
		traceId := TraceIDFromMessage(msgId)
		rootSpan := SpanID(msgId, "msg_sent")
		sourceChain, _ := chain_selectors.GetChainDetailsByChainIDAndFamily(strconv.FormatInt(msgSent.ChainID, 10), chain_selectors.FamilyEVM)
		sourceChainSelector := sourceChain.ChainSelector
		if okExec {
			spans = append(spans, Span{
				TraceId:           traceId,
				SpanId:            rootSpan,
				Name:              "msg_exec",
				StartTimeUnixNano: msgSent.BlockTimestamp * 1_000_000_000,
				EndTimeUnixNano:   msgExec.BlockTimestamp * 1_000_000_000,
				Kind:              2,
				Attributes: []Attribute{
					{
						Key: "sourceChainSelector",
						Value: map[string]any{
							"stringValue": strconv.FormatUint(sourceChainSelector, 10),
						},
					},
					{
						Key: "destChainSelector",
						Value: map[string]any{
							"stringValue": strconv.FormatUint(msgSent.UnpackedData.DestChainSelector, 10),
						},
					},
					{
						Key: "messageId",
						Value: map[string]any{
							"stringValue": msgId.String(),
						},
					},
				},
			})
		} else {
			// open span
			spans = append(spans, Span{
				TraceId:           traceId,
				SpanId:            rootSpan,
				Name:              "msg_exec",
				StartTimeUnixNano: msgSent.BlockTimestamp * 1_000_000_000,
				EndTimeUnixNano:   msgSent.BlockTimestamp * 1_000_000_000,
				Kind:              2,
				Attributes: []Attribute{
					{
						Key: "sourceChainSelector",
						Value: map[string]any{
							"stringValue": strconv.FormatUint(sourceChainSelector, 10),
						},
					},
					{
						Key: "destChainSelector",
						Value: map[string]any{
							"stringValue": strconv.FormatUint(msgSent.UnpackedData.DestChainSelector, 10),
						},
					},
					{
						Key: "messageId",
						Value: map[string]any{
							"stringValue": msgId.String(),
						},
					},
				},
			})
		}
		if okSig {
			spans = append(spans, Span{
				TraceId:           traceId,
				ParentSpanId:      rootSpan,
				SpanId:            SpanID(msgId, "msg_sig"),
				Name:              "msg_sig",
				StartTimeUnixNano: msgSent.BlockTimestamp * 1_000_000_000,
				EndTimeUnixNano:   uint64(msgSig.Timestamp) * 1_000_000_000,
				Kind:              2,
				Attributes: []Attribute{
					{
						Key: "sourceChainSelector",
						Value: map[string]any{
							"stringValue": msgSig.SourceChainSelector.String(),
						},
					},
					{
						Key: "destChainSelector",
						Value: map[string]any{
							"stringValue": msgSig.DestChainSelector.String(),
						},
					},
					{
						Key: "messageId",
						Value: map[string]any{
							"stringValue": msgId.String(),
						},
					},
				},
			})
		}
		if err := tp.PushTrace(spans); err != nil {
			return fmt.Errorf("failed to push traces: %w", err)
		}
	}
	Plog.Info().Str("LokiStreamURL", LokiOnChainStreamURL).Send()
	Plog.Info().Str("PrometheusMetrics", PromMetrics).Send()
	return nil
}

// TraceIDFromMessage derives traceId from messageId
// Input: [32]byte messageId
// Output: 32 hex chars (traceId), 16 hex chars (spanId)
func TraceIDFromMessage(msgID [32]byte) string {
	sum := sha256.Sum256(msgID[:])
	trace := sum[:16]
	// Disallow all-zero (spec)
	allZero := true
	for _, b := range trace {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		trace[0] = 1
	}

	return hex.EncodeToString(trace) // 32 hex chars
}

// SpanID derives a deterministic 8-byte span id from message id + span name.
// If key == nil or empty, falls back to plain SHA-256.
func SpanID(msgID [32]byte, spanName string) string {
	h := sha256.New()
	h.Write(msgID[:])
	h.Write([]byte(spanName))
	sum := h.Sum(nil)
	span := sum[len(sum)-8:] // take last 8 bytes

	// Disallow all-zero span id (spec)
	allZero := true
	for _, b := range span {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		span[0] = 1
	}

	return hex.EncodeToString(span) // 16 hex chars
}
