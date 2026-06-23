package cli

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
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
// Each span is sent exactly ONCE, in its fully completed final form, when its end time
// falls within the current phase window (prevCutoff, currentCutoff]. No span is ever
// re-sent or mutated. A new random traceId (messageId) is generated each run.
//
// Span end times (ms from t0) — which phase delivers each span:
//
//	phase 3 (+4500ms):  finalization(4000)
//	phase 4 (+6500ms):  nop-1(5250) nop-2(5700) nop-3/5/aggregator(6100) indexer.poll_agg(6300)
//	phase 5 (+9300ms):  verification/token-verifier(7800) indexer.poll_tv/ingest(8000) nop-4(9200)
//	phase 6 (+15000ms): root/execution/executor-2(13100) executor-1(15000)
//
// Phases 1 (+0ms) and 2 (+3750ms) have no completed spans — interval still fires.
var pushMockTraceCmd = &cobra.Command{
	Use:   "push-mock-trace",
	Short: "Incrementally push a synthetic CCIP trace to OTLP (tests VictoriaTraces dedup/merge)",
	RunE:  runPushMockTrace,
}

func init() {
	pushMockTraceCmd.Flags().String("endpoint", "localhost:4317", "OTLP gRPC endpoint")
	pushMockTraceCmd.Flags().Duration("interval", 30*time.Second, "Interval between phase pushes")
	pushMockTraceCmd.Flags().Bool("dump", false, "Print each OTLP request as JSON before sending")
	pushMockTraceCmd.Flags().Bool("full", false, "Send all spans in one shot")
	pushMockTraceCmd.Flags().String("t0", "", "Trace start time in RFC3339 format (default: now)")
}

// phaseCutoffsMs are the upper bounds (ms from t0) for each incremental push window.
// A span is delivered in the first phase where currentCutoff >= span.endMs.
var phaseCutoffsMs = []int64{0, 3750, 4500, 6500, 9300, 15000}

func runPushMockTrace(cmd *cobra.Command, _ []string) error {
	endpoint, _ := cmd.Flags().GetString("endpoint")
	interval, _ := cmd.Flags().GetDuration("interval")
	dump, _ := cmd.Flags().GetBool("dump")
	full, _ := cmd.Flags().GetBool("full")
	t0Str, _ := cmd.Flags().GetString("t0")

	ctx := cmd.Context()

	messageID := randomMessageID()

	var newT0 time.Time
	if t0Str != "" {
		parsed, err := time.Parse(time.RFC3339, t0Str)
		if err != nil {
			return fmt.Errorf("invalid --t0 %q: %w", t0Str, err)
		}
		newT0 = parsed
	} else {
		newT0 = time.Now()
	}

	fmt.Printf("trace messageId: %s\n", messageID)
	fmt.Printf("trace traceId:   0x%s\n", messageID[2:34])
	fmt.Printf("trace t0:        %s\n", newT0.UTC().Format(time.RFC3339))

	client := otlptracegrpc.NewClient(
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithEndpoint(endpoint),
	)
	if err := client.Start(ctx); err != nil {
		return fmt.Errorf("start OTLP client: %w", err)
	}
	defer func() { _ = client.Stop(ctx) }()

	hardcodedT0 := viz.MustMicros("2026-06-01T15:48:29Z")
	t0micros := newT0.UnixMicro()
	delta := t0micros - hardcodedT0

	trace := shiftTraceTime(replaceMessageID(viz.BuildTrace(), messageID), delta)

	cutoffs := phaseCutoffsMs
	if full {
		cutoffs = phaseCutoffsMs[len(phaseCutoffsMs)-1:]
	}

	marshaler := protojson.MarshalOptions{Multiline: true}
	prevCutoffMs := int64(-1)

	for i, cutoffMs := range cutoffs {
		resourceSpans := buildIncrementalPhaseSpans(trace, t0micros, prevCutoffMs, cutoffMs, messageID)
		prevCutoffMs = cutoffMs

		totalSpans := 0
		for _, rs := range resourceSpans {
			for _, ss := range rs.ScopeSpans {
				totalSpans += len(ss.Spans)
			}
		}

		if totalSpans == 0 {
			fmt.Printf("phase %d/%d — +%dms: nothing completed yet\n", i+1, len(cutoffs), cutoffMs)
		} else {
			if dump {
				fmt.Printf("=== phase %d/%d (+%dms, %d spans) ===\n", i+1, len(cutoffs), cutoffMs, totalSpans)
				for _, rs := range resourceSpans {
					b, err := marshaler.Marshal(proto.Message(rs))
					if err == nil {
						fmt.Println(bytesFieldsToHex(string(b)))
					}
				}
				fmt.Println()
			}

			if err := client.UploadTraces(ctx, resourceSpans); err != nil {
				return fmt.Errorf("phase %d/%d upload failed: %w", i+1, len(cutoffs), err)
			}
			fmt.Printf("phase %d/%d pushed — +%dms, %d spans\n", i+1, len(cutoffs), cutoffMs, totalSpans)
		}

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

// buildIncrementalPhaseSpans returns spans whose end time falls in (prevCutoffMs, cutoffMs].
// Each span is sent in final complete form with all events — it will never be re-sent.
func buildIncrementalPhaseSpans(trace viz.Trace, t0micros, prevCutoffMs, cutoffMs int64, messageID string) []*tracepb.ResourceSpans {
	msToMicros := int64(time.Millisecond / time.Microsecond)
	prevEndMicros := t0micros + prevCutoffMs*msToMicros
	endMicros := t0micros + cutoffMs*msToMicros
	traceIDBytes := mustDecodeHex(messageID[2:34]) // first 16 bytes of messageId as traceId

	byProcess := map[string][]viz.Span{}
	for _, s := range trace.Spans {
		spanEndMicros := s.StartTime + s.Duration
		if spanEndMicros > prevEndMicros && spanEndMicros <= endMicros {
			byProcess[s.ProcessID] = append(byProcess[s.ProcessID], s)
		}
	}

	var resourceSpans []*tracepb.ResourceSpans
	for pid, spans := range byProcess {
		proc := trace.Processes[pid]

		otlpSpans := make([]*tracepb.Span, 0, len(spans))
		for _, s := range spans {
			otlpSpans = append(otlpSpans, &tracepb.Span{
				TraceId:           traceIDBytes,
				SpanId:            mustDecodeHex(s.SpanID),
				ParentSpanId:      parentSpanIDBytes(s.References),
				Name:              s.OperationName,
				Kind:              spanKindFromTags(s.Tags),
				StartTimeUnixNano: uint64(s.StartTime) * 1000,
				EndTimeUnixNano:   uint64(s.StartTime+s.Duration) * 1000,
				Attributes:        tagsToAttrs(s.Tags),
				Events:            allEvents(s.Logs),
				Status:            spanStatus(s.Tags, false),
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

// allEvents converts all span logs to OTLP events with no time filtering.
func allEvents(logs []viz.SpanLog) []*tracepb.Span_Event {
	events := make([]*tracepb.Span_Event, 0, len(logs))
	for _, l := range logs {
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

// shiftTraceTime adds deltaUs microseconds to every span StartTime and log Timestamp.
func shiftTraceTime(trace viz.Trace, deltaUs int64) viz.Trace {
	for i := range trace.Spans {
		s := &trace.Spans[i]
		s.StartTime += deltaUs
		for j := range s.Logs {
			s.Logs[j].Timestamp += deltaUs
		}
	}
	return trace
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

// randomMessageID returns a random 32-byte value as a 0x-prefixed hex string.
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

// bytesFieldsToHex converts base64-encoded byte fields in protojson output to hex strings.
// Covers traceId, spanId, and parentSpanId.
var reBase64Bytes = regexp.MustCompile(`"(traceId|spanId|parentSpanId)":\s*"([A-Za-z0-9+/]+=*)"`)

func bytesFieldsToHex(j string) string {
	return reBase64Bytes.ReplaceAllStringFunc(j, func(match string) string {
		sub := reBase64Bytes.FindStringSubmatch(match)
		if len(sub) < 3 {
			return match
		}
		raw, err := base64.StdEncoding.DecodeString(sub[2])
		if err != nil {
			return match
		}
		return fmt.Sprintf(`"%s":  "0x%s"`, sub[1], hex.EncodeToString(raw))
	})
}

func mustDecodeHex(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid hex %q: %v", s, err))
	}
	return b
}
