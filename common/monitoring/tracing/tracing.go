package tracing

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand/v2"

	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// TraceIDForMessage derives a deterministic OTel TraceID from a message ID so
// that spans for the same message land in a single trace even when no real
// parent context is available yet (e.g. the very first span for a message).
func TraceIDForMessage(messageID protocol.Bytes32) oteltrace.TraceID {
	var traceID oteltrace.TraceID
	copy(traceID[:], messageID[:16])
	return traceID
}

// randomSpanID generates a random OTel SpanID. Only the TraceID is derived
// from the message ID; the (pseudo-parent) SpanID must stay random per the
// OTel spec.
func randomSpanID() oteltrace.SpanID {
	var spanID oteltrace.SpanID
	if _, err := rand.Read(spanID[:]); err != nil {
		binary.LittleEndian.PutUint64(spanID[:], mrand.Uint64()) //nolint:gosec // G404: fallback
	}
	return spanID
}

// SpanContextForMessage returns a remote SpanContext whose TraceID is
// deterministically derived from messageID and whose SpanID is random.
func SpanContextForMessage(messageID protocol.Bytes32) oteltrace.SpanContext {
	return oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID:    TraceIDForMessage(messageID),
		SpanID:     randomSpanID(),
		TraceFlags: oteltrace.FlagsSampled,
		Remote:     true,
	})
}

// TraceContextForMessage returns ctx carrying messageID's deterministic
// SpanContext as the current span.
func TraceContextForMessage(ctx context.Context, messageID protocol.Bytes32) context.Context {
	return oteltrace.ContextWithSpanContext(ctx, SpanContextForMessage(messageID))
}

// SpanFromContext returns the span carried by ctx. Unlike oteltrace.SpanFromContext,
// it tolerates a nil ctx (e.g. a VerificationTask whose TraceContext was never
// populated) by returning the no-op span instead of panicking, so call sites
// don't each need their own "is TraceContext nil" guard before use.
func SpanFromContext(ctx context.Context) oteltrace.Span {
	if ctx == nil {
		return oteltrace.SpanFromContext(context.Background())
	}
	return oteltrace.SpanFromContext(ctx)
}

// Tracing exposes span creation for the message pipeline.
type Tracing interface {
	// StartMessageSpan starts a span for messageID. If ctx already carries a
	// valid span context (a real in-process parent, e.g. the message's
	// discovery span or a previous attempt), that parent is used; otherwise a
	// deterministic parent derived from messageID is synthesized, so the span
	// still lands in a consistent per-message trace.
	StartMessageSpan(ctx context.Context, name string, messageID protocol.Bytes32, attrs ...attribute.KeyValue) (context.Context, oteltrace.Span)
}

type messageTracing struct {
	tracer oteltrace.Tracer
}

// NewTracing returns a Tracing backed by tracer.
func NewTracing(tracer oteltrace.Tracer) Tracing {
	return &messageTracing{tracer: tracer}
}

func withMessageID(messageID string, attrs []attribute.KeyValue) []attribute.KeyValue {
	return append([]attribute.KeyValue{attribute.String(MessageIDKey, messageID)}, attrs...)
}

func (t *messageTracing) StartMessageSpan(ctx context.Context, name string, messageID protocol.Bytes32, attrs ...attribute.KeyValue) (context.Context, oteltrace.Span) {
	tCtx := ctx
	if tCtx == nil {
		tCtx = context.Background()
	}
	if !oteltrace.SpanContextFromContext(tCtx).IsValid() {
		tCtx = TraceContextForMessage(tCtx, messageID)
	}
	return t.tracer.Start(tCtx, name, oteltrace.WithAttributes(withMessageID(messageID.String(), attrs)...))
}
