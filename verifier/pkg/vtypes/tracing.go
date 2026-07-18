package vtypes

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// TraceIDForMessage derives a deterministic OTel TraceID from a message ID so that
// spans emitted by independent, queue-decoupled pipeline stages (source reader,
// task verifier, storage writer) for the same message land in a single trace.
func TraceIDForMessage(messageID string) oteltrace.TraceID {
	sum := sha256.Sum256([]byte(messageID))
	var traceID oteltrace.TraceID
	copy(traceID[:], sum[:16])
	return traceID
}

// randomSpanID generates a random OTel SpanID. Only the TraceID is derived from the
// message ID; the (pseudo-parent) SpanID must stay random per the OTel spec.
func randomSpanID() oteltrace.SpanID {
	var spanID oteltrace.SpanID
	_, _ = rand.Read(spanID[:])
	return spanID
}

// SpanContextForMessage returns a remote SpanContext whose TraceID is deterministically
// derived from messageID and whose SpanID is random. Use as a parent (via
// TraceContextForMessage) or as a Link target for spans that touch multiple messages.
func SpanContextForMessage(messageID string) oteltrace.SpanContext {
	return oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID:    TraceIDForMessage(messageID),
		SpanID:     randomSpanID(),
		TraceFlags: oteltrace.FlagsSampled,
		Remote:     true,
	})
}

// TraceContextForMessage returns ctx carrying messageID's deterministic SpanContext
// as the current span. Starting a span with the returned context as parent joins
// that span into the message's single trace, even across process/queue boundaries
// where no real trace context propagation exists.
func TraceContextForMessage(ctx context.Context, messageID string) context.Context {
	return oteltrace.ContextWithSpanContext(ctx, SpanContextForMessage(messageID))
}

// messageSpanEntry is the global span open for a message, plus the context
// carrying it so later stages can start real children under it.
type messageSpanEntry struct {
	span oteltrace.Span
	ctx  context.Context
}

// messageTracing is the concrete Tracing implementation, backed by a single
// otel Tracer and an in-memory registry of each in-flight message's global span.
type messageTracing struct {
	tracer oteltrace.Tracer

	mu    sync.Mutex
	spans map[string]messageSpanEntry
}

// NewTracing returns a Tracing backed by tracer.
func NewTracing(tracer oteltrace.Tracer) Tracing {
	return &messageTracing{
		tracer: tracer,
		spans:  make(map[string]messageSpanEntry),
	}
}

func withMessageID(messageID string, attrs []attribute.KeyValue) []attribute.KeyValue {
	return append([]attribute.KeyValue{attribute.String("message_id", messageID)}, attrs...)
}

func (t *messageTracing) StartMessageSpan(ctx context.Context, name, messageID string, attrs ...attribute.KeyValue) (context.Context, oteltrace.Span) {
	tCtx := ctx
	if !oteltrace.SpanContextFromContext(ctx).IsValid() {
		// No real parent propagated (e.g. cross-process boundary with no
		// W3C traceparent available, or a fresh restart) - fall back to the
		// deterministic, messageID-derived synthetic parent so this span
		// still lands in the message's single trace.
		tCtx = TraceContextForMessage(ctx, messageID)
	}
	return t.tracer.Start(tCtx, name, oteltrace.WithAttributes(withMessageID(messageID, attrs)...))
}