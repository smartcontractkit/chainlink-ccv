package ccv_evm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/go-resty/resty/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	DefaultLokiURL  = "http://localhost:3030/loki/api/v1/push"
	DefaultTempoURL = "http://localhost:4318/v1/traces"
)

/*
Loki labels.
*/
const (
	LokiCCIPMessageSentLabel       = "on-chain-sent"
	LokiExecutionStateChangedLabel = "on-chain-exec"
)

/*
Prometheus metrics.
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

// LaneStreamConfig contains contracts to collect events from and selectors for queries.
type LaneStreamConfig struct {
	FromSelector      uint64
	ToSelector        uint64
	AggregatorAddress string
	AggregatorSince   int64
}

// LaneStreams represents all the events for sent/exec events.
type LaneStreams struct {
	SentEvents    []*onramp.OnRampCCIPMessageSent
	ExecEvents    []*offramp.OffRampExecutionStateChanged
	Verifications []protocol.QueryResponse
}

type SentEventPlusMeta struct {
	*onramp.OnRampCCIPMessageSent
	MessageIDHex string
}

type ExecEventPlusMeta struct {
	*offramp.OffRampExecutionStateChanged
	MessageIDHex string
}

func ToAnySlice[T any](slice []T) []any {
	result := make([]any, len(slice))
	for i, v := range slice {
		result[i] = v
	}
	return result
}

// ProcessLaneEvents collects, pushes and observes sent and executed messages for lane.
func ProcessLaneEvents(ctx context.Context, c *CCIP17EVM, lp *LokiPusher, tp *TempoPusher, cfg *LaneStreamConfig) error {
	lggr := zerolog.Ctx(ctx)
	lggr.Info().Uint64("FromSelector", cfg.FromSelector).Uint64("ToSelector", cfg.ToSelector).Msg("Processing events")
	streams, err := FetchLaneEvents(ctx, c, cfg)
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
	if err := tp.PushTrace(ctx, StreamsToSpans(fromSelectorStr, toSelectorStr, streams)); err != nil {
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
		lggr.Debug().
			Any("MsgID", hexutil.Encode(l.MessageId[:])).
			Uint64("Seconds", elapsed).
			Msg("Elapsed time")
		srcDstLatency.WithLabelValues(fromSelectorStr, toSelectorStr).Observe(float64(elapsed))
		msgExecTotal.WithLabelValues(fromSelectorStr, toSelectorStr).Inc()
	}
	return nil
}

func StreamsToSpans(srcSelector, destSelector string, streams *LaneStreams) []Span {
	idToMsgSent := make(map[protocol.Bytes32]*onramp.OnRampCCIPMessageSent)
	idToMsgExec := make(map[protocol.Bytes32]*offramp.OffRampExecutionStateChanged)
	idToReport := make(map[protocol.Bytes32]*protocol.CCVData)
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
	for msgID, msgSent := range idToMsgSent {
		msgSig, okSig := idToReport[msgID]
		msgExec, okExec := idToMsgExec[msgID]
		traceID := TraceIDFromMessage(msgID)
		rootSpan := SpanID(msgID, "msg_sent")
		if okExec {
			spans = append(spans, Span{
				TraceID:           traceID,
				SpanID:            rootSpan,
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
							"stringValue": msgID.String(),
						},
					},
				},
			})
		} else {
			// open span
			spans = append(spans, Span{
				TraceID:           traceID,
				SpanID:            rootSpan,
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
							"stringValue": msgID.String(),
						},
					},
				},
			})
		}
		if okSig {
			spans = append(spans, Span{
				TraceID:           traceID,
				ParentSpanID:      rootSpan,
				SpanID:            SpanID(msgID, "msg_sig"),
				Name:              "msg_sig",
				StartTimeUnixNano: msgSent.Raw.BlockTimestamp * 1_000_000_000,
				EndTimeUnixNano:   uint64(msgSig.Timestamp.Nanosecond()), //nolint:gosec // conversion from int to uint64 is safe here
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
							"stringValue": msgID.String(),
						},
					},
				},
			})
		}
	}
	return spans
}

// FetchLaneEvents fetch sent and exec events for lane.
func FetchLaneEvents(ctx context.Context, c *CCIP17EVM, cfg *LaneStreamConfig) (*LaneStreams, error) {
	msgSentEvent, err := c.fetchAllSentEventsBySelector(ctx, cfg.FromSelector, cfg.ToSelector)
	if err != nil {
		return nil, err
	}
	execEvents, err := c.fetchAllExecEventsBySelector(ctx, cfg.ToSelector, cfg.FromSelector)
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

func FetchAllVerifications(ctx context.Context, aggregatorAddress string, aggregatorSince int64) ([]protocol.QueryResponse, error) {
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.DebugLevel))
	if err != nil {
		return nil, fmt.Errorf("failed to create monitoring logger: %w", err)
	}

	hmacConfig := hmac.ClientConfig{
		APIKey: "dev-api-key-monitoring",
		Secret: "dev-secret-monitoring",
	}

	// Use monitoring API key and secret for infrastructure access
	reader, err := storageaccess.NewAggregatorReader(
		aggregatorAddress,
		lggr,
		aggregatorSince,
		&hmacConfig,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create aggregator reader: %w", err)
	}
	return reader.ReadCCVData(ctx)
}

func addSentMetadata(msgs []*onramp.OnRampCCIPMessageSent) []*SentEventPlusMeta {
	events := make([]*SentEventPlusMeta, 0)
	for _, msg := range msgs {
		events = append(events, &SentEventPlusMeta{
			OnRampCCIPMessageSent: msg,
			MessageIDHex:          hexutil.Encode(msg.MessageId[:]),
		})
	}
	return events
}

func addExecMetadata(msgs []*offramp.OffRampExecutionStateChanged) []*ExecEventPlusMeta {
	events := make([]*ExecEventPlusMeta, 0)
	for _, msg := range msgs {
		events = append(events, &ExecEventPlusMeta{
			OffRampExecutionStateChanged: msg,
			MessageIDHex:                 hexutil.Encode(msg.MessageId[:]),
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
	h.Write(msgID[:])         //nolint // SHA-256 doesn't return an error here
	h.Write([]byte(spanName)) //nolint // SHA-256 doesn't return an error here
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

// LokiPusher handles pushing logs to Loki
// it does not use Promtail client specifically to avoid dep hell between Prometheus/Loki go deps.
type LokiPusher struct {
	lokiURL string
	client  *resty.Client
}

// LogEntry represents a single log entry for Loki.
type LogEntry struct {
	Timestamp time.Time         `json:"timestamp"`
	Message   any               `json:"message"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// LokiStream represents a stream of log entries with labels.
type LokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"` // [timestamp, log line]
}

// LokiPayload represents the payload structure for Loki API.
type LokiPayload struct {
	Streams []LokiStream `json:"streams"`
}

// NewLokiPusher creates a new LokiPusher instance.
func NewLokiPusher() *LokiPusher {
	lokiURL := os.Getenv("LOKI_URL")
	if lokiURL == "" {
		lokiURL = DefaultLokiURL
	}
	return &LokiPusher{
		lokiURL: lokiURL,
		client:  resty.New().SetTimeout(10 * time.Second),
	}
}

// Push pushes all the messages to a Loki stream.
func (lp *LokiPusher) Push(msgs []any, labels map[string]string) error {
	if len(msgs) == 0 {
		return nil
	}
	values := make([][]string, 0, len(msgs))

	for i := 0; i < len(msgs); i++ {
		combinedMessage := map[string]any{
			"log": msgs[i],
			"ts":  time.Now().Format(time.RFC3339Nano),
		}
		jsonBytes, err := json.Marshal(combinedMessage)
		if err != nil {
			return fmt.Errorf("failed to marshal combined message: %w", err)
		}
		values = append(values, []string{
			fmt.Sprintf("%d", time.Now().UnixNano()),
			string(jsonBytes),
		})
	}

	stream := LokiStream{
		Stream: labels,
		Values: values,
	}
	resp, err := lp.client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(LokiPayload{
			Streams: []LokiStream{stream},
		}).
		Post(lp.lokiURL)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	if resp.StatusCode() != 200 && resp.StatusCode() != 204 {
		return fmt.Errorf("loki returned status %d: %s", resp.StatusCode(), resp.String())
	}
	return nil
}

type TempoPayload struct {
	ResourceSpans []ResourceSpan `json:"resourceSpans"`
}

type ResourceSpan struct {
	Resource   Scope       `json:"resource"`
	ScopeSpans []ScopeSpan `json:"scopeSpans"`
}

type ScopeSpan struct {
	Scope Scope  `json:"scope"`
	Spans []Span `json:"spans"`
}

type Scope struct {
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	Attributes []Attribute `json:"attributes"`
}

type Span struct {
	TraceID           string      `json:"traceId"`
	ParentSpanID      string      `json:"parentSpanId,omitempty"`
	SpanID            string      `json:"spanId"`
	Name              string      `json:"name"`
	StartTimeUnixNano uint64      `json:"startTimeUnixNano"`
	EndTimeUnixNano   uint64      `json:"endTimeUnixNano"`
	Kind              uint8       `json:"kind"`
	Attributes        []Attribute `json:"attributes"`
}

type Attribute struct {
	Key   string         `json:"key"`
	Value map[string]any `json:"value"`
}

// TempoPusher handles pushing traces to Tempo.
type TempoPusher struct {
	tempoURL string
	client   *resty.Client
}

// NewTempoPusher creates a new TempoPusher instance.
func NewTempoPusher() *TempoPusher {
	tempoURL := os.Getenv("TEMPO_URL")
	if tempoURL == "" {
		tempoURL = DefaultTempoURL
	}
	return &TempoPusher{
		tempoURL: tempoURL,
		client:   resty.New().SetTimeout(10 * time.Second),
	}
}

func (tp *TempoPusher) PushTrace(ctx context.Context, spans []Span) error {
	l := zerolog.Ctx(ctx)
	l.Info().Msgf("Pushing spans to %v", tp.tempoURL)
	payload := TempoPayload{
		ResourceSpans: []ResourceSpan{
			{
				Resource: Scope{
					Attributes: []Attribute{
						{
							Key: "service.name",
							Value: map[string]any{
								"stringValue": "on-chain",
							},
						},
					},
				},
				ScopeSpans: []ScopeSpan{
					{
						Scope: Scope{
							Name:    "name",
							Version: "version",
							Attributes: []Attribute{
								{
									Key: "name",
									Value: map[string]any{
										"stringValue": "on-chain",
									},
								},
							},
						},
						Spans: spans,
					},
				},
			},
		},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	l.Info().Msgf("Payload: %v", string(jsonPayload))
	resp, err := tp.client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(payload).
		Post(tp.tempoURL)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	if resp.StatusCode() != 200 && resp.StatusCode() != 204 {
		return fmt.Errorf("tempo returned status %d: %s", resp.StatusCode(), resp.String())
	}
	return nil
}
