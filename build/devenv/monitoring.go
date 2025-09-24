package ccv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	ccvAggregator "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
	ccvProxy "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_proxy"
)

/*
Loki labels
*/
const (
	LokiCCIPMessageSentLabel       = "on-chain-sent"
	LokiExecutionStateChangedLabel = "on-chain-exec"
)

/*
Prometheus metrics
*/
var (
	msgSentTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "msg_sent_total",
		Help: "Total number of CCIP messages sent",
	}, []string{"from", "to"})
	msgExecTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "msg_exec_total",
		Help: "Total number of CCIP messages executed",
	}, []string{"from", "to"})
	srcDstLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "msg_src_dst_duration_seconds",
		Help:    "Total duration of processing message from src to dst chain",
		Buckets: []float64{1, 2, 5, 10, 15, 20, 30, 45, 60, 90, 120, 180, 240, 300, 400, 500},
	}, []string{"from", "to"})
)

// LaneStreamConfig contains contracts to collect events from and selectors for queries
type LaneStreamConfig struct {
	From              *ccvProxy.CCVProxy
	To                *ccvAggregator.CCVAggregator
	FromSelector      uint64
	ToSelector        uint64
	AggregatorAddress string
	AggregatorSince   int64
}

// LaneStreams represents all the events for sent/exec events
type LaneStreams struct {
	SentEvents    []*ccvProxy.CCVProxyCCIPMessageSent
	ExecEvents    []*ccvAggregator.CCVAggregatorExecutionStateChanged
	Verifications []types.QueryResponse
}

type SentEventPlusMeta struct {
	*ccvProxy.CCVProxyCCIPMessageSent
	MessageIDHex string
}

type ExecEventPlusMeta struct {
	*ccvAggregator.CCVAggregatorExecutionStateChanged
	MessageIDHex string
}

// MonitorOnChainLogs is converting specified on-chain events (logs) to Loki/Prometheus data
// it does not preserve original timestamps for observation and Loki pushes and scans/uploads the whole range
// in case we need to get realtime metrics this function can be converted to a service that calls this function with
// block ranges for both chains.
func MonitorOnChainLogs(in *Cfg) (*prometheus.Registry, error) {
	ctx := context.Background()
	msgSentTotal.Reset()
	msgExecTotal.Reset()
	srcDstLatency.Reset()

	reg := prometheus.NewRegistry()
	reg.MustRegister(msgSentTotal, msgExecTotal, srcDstLatency)

	lp := NewLokiPusher()
	tp := NewTempoPusher()
	c, err := NewContracts(in)
	if err != nil {
		return nil, err
	}
	err = ProcessLaneEvents(ctx, lp, tp, &LaneStreamConfig{
		From:              c.Proxy1337,
		To:                c.Agg2337,
		FromSelector:      c.Chain1337Details.ChainSelector,
		ToSelector:        c.Chain2337Details.ChainSelector,
		AggregatorAddress: "localhost:50001",
		AggregatorSince:   0,
	})
	if err != nil {
		return nil, err
	}
	err = ProcessLaneEvents(ctx, lp, tp, &LaneStreamConfig{
		From:              c.Proxy2337,
		To:                c.Agg1337,
		FromSelector:      c.Chain2337Details.ChainSelector,
		ToSelector:        c.Chain1337Details.ChainSelector,
		AggregatorAddress: "localhost:50001",
		AggregatorSince:   0,
	})
	if err != nil {
		return nil, err
	}
	return reg, nil
}

// ProcessLaneEvents collects, pushes and observes sent and executed messages for lane
func ProcessLaneEvents(ctx context.Context, lp *LokiPusher, tp *TempoPusher, cfg *LaneStreamConfig) error {
	Plog.Info().Uint64("FromSelector", cfg.FromSelector).Uint64("ToSelector", cfg.ToSelector).Msg("Processing events")
	streams, err := FetchLaneEvents(ctx, cfg)
	if err != nil {
		return err
	}
	fromSelectorStr := fmt.Sprintf("%d", cfg.FromSelector)
	toSelectorStr := fmt.Sprintf("%d", cfg.ToSelector)
	// push Loki streams
	if err := lp.Push(ToAnySlice(addSentMetadata(streams.SentEvents)), map[string]string{
		"job":  LokiCCIPMessageSentLabel,
		"from": fromSelectorStr,
		"to":   toSelectorStr,
	}); err != nil {
		return err
	}
	if err := lp.Push(ToAnySlice(addExecMetadata(streams.ExecEvents)), map[string]string{
		"job":  LokiExecutionStateChangedLabel,
		"from": fromSelectorStr,
		"to":   toSelectorStr,
	}); err != nil {
		return err
	}
	if err := tp.PushTrace(StreamsToSpans(fromSelectorStr, toSelectorStr, streams)); err != nil {
		return fmt.Errorf("failed to push traces: %w", err)
	}

	// observe as Prometheus metrics
	logTimeByMsgID := make(map[[32]byte]uint64)
	for _, l := range streams.SentEvents {
		logTimeByMsgID[l.MessageId] = l.Raw.BlockTimestamp
		msgSentTotal.WithLabelValues(fromSelectorStr, toSelectorStr).Inc()
	}
	for _, l := range streams.ExecEvents {
		blkTimeStarted, ok := logTimeByMsgID[l.MessageId]
		if !ok {
			continue
		}
		elapsed := l.Raw.BlockTimestamp - blkTimeStarted
		Plog.Debug().
			Any("MsgID", hexutil.Encode(l.MessageId[:])).
			Uint64("Seconds", elapsed).
			Msg("Elapsed time")
		srcDstLatency.WithLabelValues(fromSelectorStr, toSelectorStr).Observe(float64(elapsed))
		msgExecTotal.WithLabelValues(fromSelectorStr, toSelectorStr).Inc()
	}
	return nil
}

func StreamsToSpans(srcSelector string, destSelector string, streams *LaneStreams) []Span {
	idToMsgSent := make(map[types.Bytes32]*ccvProxy.CCVProxyCCIPMessageSent)
	idToMsgExec := make(map[types.Bytes32]*ccvAggregator.CCVAggregatorExecutionStateChanged)
	idToReport := make(map[types.Bytes32]*types.CCVData)
	for _, event := range streams.SentEvents {
		idToMsgSent[event.MessageId] = event
	}
	for _, event := range streams.ExecEvents {
		idToMsgExec[event.MessageId] = event
	}
	for _, event := range streams.Verifications {
		idToReport[event.Data.MessageID] = &event.Data
	}
	spans := make([]Span, 0, len(idToMsgSent))
	for msgId, msgSent := range idToMsgSent {
		msgSig, okSig := idToReport[msgId]
		msgExec, okExec := idToMsgExec[msgId]
		traceId := TraceIDFromMessage(msgId)
		rootSpan := SpanID(msgId, "msg_sent")
		if okExec {
			spans = append(spans, Span{
				TraceId:           traceId,
				SpanId:            rootSpan,
				Name:              "msg_exec",
				StartTimeUnixNano: msgSent.Raw.BlockTimestamp * 1_000_000_000,
				EndTimeUnixNano:   msgExec.Raw.BlockTimestamp * 1_000_000_000,
				Kind:              2,
				Attributes: []Attribute{
					{
						Key: "sourceChainSelector",
						Value: map[string]any{
							"stringValue": srcSelector,
						},
					},
					{
						Key: "destChainSelector",
						Value: map[string]any{
							"stringValue": destSelector,
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
				StartTimeUnixNano: msgSent.Raw.BlockTimestamp * 1_000_000_000,
				EndTimeUnixNano:   msgSent.Raw.BlockTimestamp * 1_000_000_000,
				Kind:              2,
				Attributes: []Attribute{
					{
						Key: "sourceChainSelector",
						Value: map[string]any{
							"stringValue": destSelector,
						},
					},
					{
						Key: "destChainSelector",
						Value: map[string]any{
							"stringValue": destSelector,
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
				StartTimeUnixNano: msgSent.Raw.BlockTimestamp * 1_000_000_000,
				EndTimeUnixNano:   uint64(msgSig.Timestamp) * 1_000_000_000,
				Kind:              2,
				Attributes: []Attribute{
					{
						Key: "sourceChainSelector",
						Value: map[string]any{
							"stringValue": srcSelector,
						},
					},
					{
						Key: "destChainSelector",
						Value: map[string]any{
							"stringValue": destSelector,
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
	}
	return spans
}

// FetchLaneEvents fetch sent and exec events for lane
func FetchLaneEvents(ctx context.Context, cfg *LaneStreamConfig) (*LaneStreams, error) {
	msgSentEvent, err := FetchAllSentEventsBySelector(cfg.From, cfg.ToSelector)
	if err != nil {
		return nil, err
	}
	execEvents, err := FetchAllExecEventsBySelector(cfg.To, cfg.FromSelector)
	if err != nil {
		return nil, err
	}
	verifications, err := FetchAllVerifications(ctx, cfg.AggregatorAddress, cfg.AggregatorSince)
	if err != nil {
		return nil, err
	}
	return &LaneStreams{
		SentEvents:    msgSentEvent,
		ExecEvents:    execEvents,
		Verifications: verifications,
	}, nil
}

func FetchAllVerifications(ctx context.Context, aggregatorAddress string, aggregatorSince int64) ([]types.QueryResponse, error) {
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	})
	if err != nil {
		return nil, err
	}
	reader, err := storageaccess.NewAggregatorReader(aggregatorAddress, lggr, aggregatorSince)
	if err != nil {
		return nil, err
	}
	return reader.ReadCCVData(ctx)
}

func addSentMetadata(msgs []*ccvProxy.CCVProxyCCIPMessageSent) []*SentEventPlusMeta {
	events := make([]*SentEventPlusMeta, 0)
	for _, msg := range msgs {
		events = append(events, &SentEventPlusMeta{
			CCVProxyCCIPMessageSent: msg,
			MessageIDHex:            hexutil.Encode(msg.MessageId[:]),
		})
	}
	return events
}

func addExecMetadata(msgs []*ccvAggregator.CCVAggregatorExecutionStateChanged) []*ExecEventPlusMeta {
	events := make([]*ExecEventPlusMeta, 0)
	for _, msg := range msgs {
		events = append(events, &ExecEventPlusMeta{
			CCVAggregatorExecutionStateChanged: msg,
			MessageIDHex:                       hexutil.Encode(msg.MessageId[:]),
		})
	}
	return events
}

// TraceIDFromMessage derives traceId from messageId
// Input: [32]byte messageId
// Output: 32 hex chars (traceId), 16 hex chars (spanId).
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
