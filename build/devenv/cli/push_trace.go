package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cli/viz"
)

// pushMockTraceCmd pushes a synthetic CCIP message trace to an OTLP collector.
//
// Each phase re-sends ALL spans visible at that cutoff, with content trimmed to that point.
// Span IDs are stable across phases — VictoriaTraces merges successive versions of each span.
// A new random messageId (= traceId) is generated each run so pushes don't collide.
//
// Span timeline (ms from t0):
//
//	root:       0 – 13100   finalization: 0 – 4000
//	verification: 4000 – 7800
//	nop-1: 4050–5250  nop-2: 4100–5700  nop-3: 4250–6100
//	nop-4: 4300–9200  nop-5/aggregator: 4000–6100
//	token-verifier: 4400–7800
//	indexer.poll_agg: 6000–6300  indexer.ingest: 6000–8000  indexer.poll_tv: 7100–8000
//	execution: 8000–13100  executor-1: 8000–15000  executor-2: 13000–13100
//
// Phases (cutoffs in ms from t0):
//
//	  0 ms — root OPEN, finalization OPEN
//	3750 ms — root OPEN, finalization OPEN (+context log)
//	4500 ms — root OPEN, finalization CLOSED; verification+all nops+aggregator+tv OPEN
//	6500 ms — +nop-1/2/3/5/aggregator/indexer.poll_agg CLOSED; nop-4/tv/ingest OPEN
//	9300 ms — +verification/tv/indexer all CLOSED, nop-4 CLOSED; execution+executor-1 OPEN
//	15000 ms — everything CLOSED (executor-2 appears, executor-1 closed)
var pushMockTraceCmd = &cobra.Command{
	Use:   "push-mock-trace",
	Short: "Incrementally push a synthetic CCIP trace to OTLP (tests VictoriaTraces dedup/merge)",
	RunE:  runPushMockTrace,
}

func init() {
	pushMockTraceCmd.Flags().String("endpoint", "localhost:4317", "OTLP gRPC endpoint")
	pushMockTraceCmd.Flags().Duration("interval", 30*time.Second, "Interval between phase pushes")
	pushMockTraceCmd.Flags().Bool("dump", false, "Print each OTLP request as JSON before sending")
	pushMockTraceCmd.Flags().Bool("full", false, "Send only the final complete trace in one shot")
}

// phaseCutoffsMs are the wall-clock offsets (ms from t0) used as snapshot cutoffs.
// Each push sends all spans that have started by the cutoff, trimmed to that moment.
var phaseCutoffsMs = []int64{0, 3750, 4500, 6500, 9300, 15000}

func runPushMockTrace(cmd *cobra.Command, _ []string) error {
	endpoint, _ := cmd.Flags().GetString("endpoint")
	interval, _ := cmd.Flags().GetDuration("interval")
	dump, _ := cmd.Flags().GetBool("dump")
	full, _ := cmd.Flags().GetBool("full")

	ctx := cmd.Context()

	messageID := randomMessageID()
	fmt.Printf("trace messageId: %s\n", messageID)

	client := otlptracegrpc.NewClient(
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithEndpoint(endpoint),
	)
	if err := client.Start(ctx); err != nil {
		return fmt.Errorf("start OTLP client: %w", err)
	}
	defer func() { _ = client.Stop(ctx) }()

	t0micros := viz.MustMicros("2026-06-01T15:48:29Z")
	trace := replaceMessageID(viz.BuildTrace(), messageID)

	cutoffs := phaseCutoffsMs
	if full {
		cutoffs = phaseCutoffsMs[len(phaseCutoffsMs)-1:]
	}

	marshaler := protojson.MarshalOptions{Multiline: true}

	for i, cutoffMs := range cutoffs {
		resourceSpans := buildMutablePhaseSpans(trace, t0micros, cutoffMs, messageID)

		totalSpans := 0
		for _, rs := range resourceSpans {
			for _, ss := range rs.ScopeSpans {
				totalSpans += len(ss.Spans)
			}
		}

		if dump {
			fmt.Printf("=== phase %d/%d (+%dms, %d spans) ===\n",
				i+1, len(cutoffs), cutoffMs, totalSpans)
			for _, rs := range resourceSpans {
				b, err := marshaler.Marshal(proto.Message(rs))
				if err == nil {
					fmt.Println(string(b))
				}
			}
			fmt.Println()
		}

		if err := client.UploadTraces(ctx, resourceSpans); err != nil {
			return fmt.Errorf("phase %d/%d upload failed: %w", i+1, len(cutoffs), err)
		}

		fmt.Printf("phase %d/%d pushed — +%dms, %d spans\n", i+1, len(cutoffs), cutoffMs, totalSpans)

		if i < len(cutoffs)-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}
		}
	}

	fmt.Println("all phases pushed")
	return nil
}

// buildMutablePhaseSpans returns all spans that have started by cutoffMs.
// Each span's end time is 0 (open) if still running at the cutoff, or its final end time if done.
// Events after the cutoff are excluded.
func buildMutablePhaseSpans(trace viz.Trace, t0micros, cutoffMs int64, messageID string) []*tracepb.ResourceSpans {
	msToMicros := int64(time.Millisecond / time.Microsecond)
	cutoffMicros := t0micros + cutoffMs*msToMicros
	traceIDBytes := mustDecodeHex(messageID[2:34]) // first 16 bytes

	byProcess := map[string][]viz.Span{}
	for _, s := range trace.Spans {
		if s.StartTime <= cutoffMicros {
			byProcess[s.ProcessID] = append(byProcess[s.ProcessID], s)
		}
	}

	var resourceSpans []*tracepb.ResourceSpans
	for pid, spans := range byProcess {
		proc := trace.Processes[pid]

		otlpSpans := make([]*tracepb.Span, 0, len(spans))
		for _, s := range spans {
			finalEndMicros := s.StartTime + s.Duration
			open := finalEndMicros > cutoffMicros

			var endTimeNano uint64
			if !open {
				endTimeNano = uint64(finalEndMicros) * 1000
			}

			otlpSpans = append(otlpSpans, &tracepb.Span{
				TraceId:           traceIDBytes,
				SpanId:            mustDecodeHex(s.SpanID),
				ParentSpanId:      parentSpanIDBytes(s.References),
				Name:              s.OperationName,
				Kind:              spanKindFromTags(s.Tags),
				StartTimeUnixNano: uint64(s.StartTime) * 1000,
				EndTimeUnixNano:   endTimeNano,
				Attributes:        tagsToAttrs(s.Tags),
				Events:            eventsUpTo(s.Logs, cutoffMicros),
				Status:            spanStatus(s.Tags, open),
			})
		}

		resourceSpans = append(resourceSpans, &tracepb.ResourceSpans{
			Resource: &resourcepb.Resource{
				Attributes: []*commonpb.KeyValue{
					strAttrOTLP("service.name", proc.ServiceName),
				},
			},
			ScopeSpans: []*tracepb.ScopeSpans{{Spans: otlpSpans}},
		})
	}

	return resourceSpans
}

// eventsUpTo returns only events whose timestamp is <= cutoffMicros.
func eventsUpTo(logs []viz.SpanLog, cutoffMicros int64) []*tracepb.Span_Event {
	var events []*tracepb.Span_Event
	for _, l := range logs {
		if l.Timestamp > cutoffMicros {
			break
		}
		name := ""
		attrs := make([]*commonpb.KeyValue, 0, len(l.Fields))
		for _, f := range l.Fields {
			if f.Key == "event" {
				if s, ok := f.Value.(string); ok {
					name = s
				}
				continue
			}
			attrs = append(attrs, kvToAttr(f))
		}
		events = append(events, &tracepb.Span_Event{
			TimeUnixNano: uint64(l.Timestamp) * 1000,
			Name:         name,
			Attributes:   attrs,
		})
	}
	return events
}

// replaceMessageID substitutes the hardcoded viz.MessageID with a dynamic one
// in all TraceID fields, references, tags, and event payloads.
func replaceMessageID(trace viz.Trace, newID string) viz.Trace {
	trace.TraceID = newID
	for i := range trace.Spans {
		s := &trace.Spans[i]
		s.TraceID = newID
		for j := range s.References {
			s.References[j].TraceID = newID
		}
		for j := range s.Tags {
			if v, ok := s.Tags[j].Value.(string); ok {
				s.Tags[j].Value = strings.ReplaceAll(v, viz.MessageID, newID)
			}
		}
		for j := range s.Logs {
			for k := range s.Logs[j].Fields {
				f := &s.Logs[j].Fields[k]
				if v, ok := f.Value.(string); ok {
					f.Value = strings.ReplaceAll(v, viz.MessageID, newID)
				}
			}
		}
	}
	return trace
}

// randomMessageID returns a random 32-byte value as an 0x-prefixed hex string,
// matching the CCIP messageId format.
func randomMessageID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("rand.Read: %v", err))
	}
	return "0x" + hex.EncodeToString(b)
}

func parentSpanIDBytes(refs []viz.Reference) []byte {
	for _, r := range refs {
		if r.RefType == "CHILD_OF" {
			return mustDecodeHex(r.SpanID)
		}
	}
	return nil
}

func spanKindFromTags(tags []viz.KeyValue) tracepb.Span_SpanKind {
	for _, t := range tags {
		if t.Key == "span.kind" {
			switch t.Value {
			case "server":
				return tracepb.Span_SPAN_KIND_SERVER
			case "client":
				return tracepb.Span_SPAN_KIND_CLIENT
			case "internal":
				return tracepb.Span_SPAN_KIND_INTERNAL
			case "consumer":
				return tracepb.Span_SPAN_KIND_CONSUMER
			case "producer":
				return tracepb.Span_SPAN_KIND_PRODUCER
			}
		}
	}
	return tracepb.Span_SPAN_KIND_INTERNAL
}

func tagsToAttrs(tags []viz.KeyValue) []*commonpb.KeyValue {
	attrs := make([]*commonpb.KeyValue, 0, len(tags))
	for _, t := range tags {
		if t.Key == "span.kind" {
			continue
		}
		attrs = append(attrs, kvToAttr(t))
	}
	return attrs
}

func spanStatus(tags []viz.KeyValue, open bool) *tracepb.Status {
	if open {
		return &tracepb.Status{Code: tracepb.Status_STATUS_CODE_UNSET}
	}
	for _, t := range tags {
		if t.Key == "error" {
			if v, ok := t.Value.(bool); ok && v {
				return &tracepb.Status{
					Code:    tracepb.Status_STATUS_CODE_ERROR,
					Message: errorMessage(tags),
				}
			}
		}
	}
	return &tracepb.Status{Code: tracepb.Status_STATUS_CODE_OK}
}

func errorMessage(tags []viz.KeyValue) string {
	for _, t := range tags {
		if t.Key == "error.message" {
			if s, ok := t.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}

func kvToAttr(kv viz.KeyValue) *commonpb.KeyValue {
	var val *commonpb.AnyValue
	switch kv.Type {
	case "bool":
		if v, ok := kv.Value.(bool); ok {
			val = &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: v}}
		}
	case "int64":
		switch v := kv.Value.(type) {
		case int:
			val = &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: int64(v)}}
		case int64:
			val = &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: v}}
		case float64:
			val = &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: int64(v)}}
		}
	}
	if val == nil {
		s := fmt.Sprintf("%v", kv.Value)
		val = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: s}}
	}
	return &commonpb.KeyValue{Key: kv.Key, Value: val}
}

func strAttrOTLP(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   k,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}},
	}
}

func mustDecodeHex(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid hex %q: %v", s, err))
	}
	return b
}
