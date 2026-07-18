package vtypes

import (
	"context"
	"crypto/rand"
	"crypto/sha256"

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
