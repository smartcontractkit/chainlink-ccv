package executor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"

	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// TraceIDForMessage derives a deterministic OTel TraceID from a message ID so
// that spans for the same message land in a single trace even when no real
// parent context is available yet (e.g. the very first span for a message).
func TraceIDForMessage(messageID string) oteltrace.TraceID {
	sum := sha256.Sum256([]byte(messageID))
	var traceID oteltrace.TraceID
	copy(traceID[:], sum[:16])
	return traceID
}

// randomSpanID generates a random OTel SpanID. Only the TraceID is derived
// from the message ID; the (pseudo-parent) SpanID must stay random per the
// OTel spec.
func randomSpanID() oteltrace.SpanID {
	var spanID oteltrace.SpanID
	_, _ = rand.Read(spanID[:])
	return spanID
}

// SpanContextForMessage returns a remote SpanContext whose TraceID is
// deterministically derived from messageID and whose SpanID is random.
func SpanContextForMessage(messageID string) oteltrace.SpanContext {
	return oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID:    TraceIDForMessage(messageID),
		SpanID:     randomSpanID(),
		TraceFlags: oteltrace.FlagsSampled,
		Remote:     true,
	})
}

// TraceContextForMessage returns ctx carrying messageID's deterministic
// SpanContext as the current span.
func TraceContextForMessage(ctx context.Context, messageID string) context.Context {
	return oteltrace.ContextWithSpanContext(ctx, SpanContextForMessage(messageID))
}

// Tracing exposes span creation for the executor pipeline. The executor's
// pipeline (subscribe -> delay heap -> worker pool -> HandleMessage) runs in
// a single process, so trace parentage is carried explicitly via
// context.Context - propagated through message_heap.MessageWithTimestamps.TraceContext
// across the delay-heap/retry boundary - rather than through any
// message_id -> span/context registry.
type Tracing interface {
	// StartMessageSpan starts a span for messageID. If ctx already carries a
	// valid span context (a real in-process parent, e.g. the message's
	// discovery span or a previous attempt), that parent is used; otherwise a
	// deterministic parent derived from messageID is synthesized, so the span
	// still lands in a consistent per-message trace.
	StartMessageSpan(ctx context.Context, name, messageID string, attrs ...attribute.KeyValue) (context.Context, oteltrace.Span)
}

type messageTracing struct {
	tracer oteltrace.Tracer
}

// NewTracing returns a Tracing backed by tracer.
func NewTracing(tracer oteltrace.Tracer) Tracing {
	return &messageTracing{tracer: tracer}
}

func withMessageID(messageID string, attrs []attribute.KeyValue) []attribute.KeyValue {
	return append([]attribute.KeyValue{attribute.String("message_id", messageID)}, attrs...)
}

func (t *messageTracing) StartMessageSpan(ctx context.Context, name, messageID string, attrs ...attribute.KeyValue) (context.Context, oteltrace.Span) {
	tCtx := ctx
	if !oteltrace.SpanContextFromContext(ctx).IsValid() {
		tCtx = TraceContextForMessage(ctx, messageID)
	}
	return t.tracer.Start(tCtx, name, oteltrace.WithAttributes(withMessageID(messageID, attrs)...))
}
