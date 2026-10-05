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

// spanContextForMessage returns a remote SpanContext whose TraceID is deterministically
// derived from messageID and whose SpanID is random. Not sampled unless alwaysSampled is
// true, in which case the configured Sampler's ratio is bypassed - see AlwaysSampled.
func spanContextForMessage(messageID protocol.Bytes32, alwaysSampled bool) oteltrace.SpanContext {
	flags := oteltrace.TraceFlags(0)
	if alwaysSampled {
		flags = oteltrace.FlagsSampled
	}
	return oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID:    TraceIDForMessage(messageID),
		SpanID:     randomSpanID(),
		TraceFlags: flags,
		Remote:     true,
	})
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

// spanConfig accumulates the options passed to one StartMessageSpan call.
type spanConfig struct {
	alwaysSampled bool
	attrs         []attribute.KeyValue
}

// SpanOption configures a single StartMessageSpan call.
type SpanOption func(*spanConfig)

// AlwaysSampled forces the span to be recorded regardless of the configured Sampler's ratio.
// Reserve it for low-volume, high-value spans (one per write/discovery); omit it for
// per-attempt/retry spans so the configured sampling ratio bounds their volume.
func AlwaysSampled() SpanOption {
	return func(c *spanConfig) { c.alwaysSampled = true }
}

// WithAttributes attaches key-value string pairs to the span, e.g. WithAttributes("k1", "v1", "k2", "v2").
func WithAttributes(kv ...string) SpanOption {
	if len(kv)%2 != 0 {
		panic("tracing.WithAttributes: odd number of key-value arguments")
	}
	return func(c *spanConfig) {
		for i := 0; i < len(kv); i += 2 {
			c.attrs = append(c.attrs, attribute.String(kv[i], kv[i+1]))
		}
	}
}

// Tracing exposes span creation for the message pipeline.
type Tracing interface {
	// StartMessageSpan starts a span for messageID, parented off ctx's span, or a synthesized
	// one otherwise (TraceID from messageID, SpanID random). A real parent's sampled flag is
	// forced to match AlwaysSampled, so it can neither suppress nor force-sample this span.
	StartMessageSpan(ctx context.Context, name string, messageID protocol.Bytes32, opts ...SpanOption) (context.Context, oteltrace.Span)
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

func (t *messageTracing) StartMessageSpan(ctx context.Context, name string, messageID protocol.Bytes32, opts ...SpanOption) (context.Context, oteltrace.Span) {
	var cfg spanConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	tCtx := ctx
	if tCtx == nil {
		tCtx = context.Background()
	}
	switch {
	case !oteltrace.SpanContextFromContext(tCtx).IsValid():
		tCtx = oteltrace.ContextWithSpanContext(tCtx, spanContextForMessage(messageID, cfg.alwaysSampled))
	default:
		// Force the parent's sampled flag to match cfg.alwaysSampled, so an inherited
		// traceparent can neither suppress nor force-sample this span either way.
		if sc := oteltrace.SpanContextFromContext(tCtx); sc.IsSampled() != cfg.alwaysSampled {
			flags := sc.TraceFlags()
			if cfg.alwaysSampled {
				flags |= oteltrace.FlagsSampled
			} else {
				flags &^= oteltrace.FlagsSampled
			}
			tCtx = oteltrace.ContextWithSpanContext(tCtx, sc.WithTraceFlags(flags))
		}
	}
	return t.tracer.Start(tCtx, name, oteltrace.WithAttributes(withMessageID(messageID.String(), cfg.attrs)...))
}
