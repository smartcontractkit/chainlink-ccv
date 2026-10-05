package tracing

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// TestStartMessageSpan_AlwaysSampledOverridesRealParent: AlwaysSampled must force sampling
// even when ctx carries a valid, unsampled real parent (regression test).
func TestStartMessageSpan_AlwaysSampledOverridesRealParent(t *testing.T) {
	// ParentBased + a ratio-0 root sampler mirrors production: a low TraceSampleRatio for
	// spans with no real parent, but a real parent's sampled flag otherwise wins.
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0))))
	defer func() { _ = tp.Shutdown(context.Background()) }()
	tr := NewTracing(tp.Tracer("test"))

	unsampledParent := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID: oteltrace.TraceID{0x01}, SpanID: oteltrace.SpanID{0x01},
		TraceFlags: 0, // not sampled - e.g. a task span opened without AlwaysSampled
	})
	ctx := oteltrace.ContextWithSpanContext(context.Background(), unsampledParent)

	_, span := tr.StartMessageSpan(ctx, "child", protocol.Bytes32{}, AlwaysSampled())
	defer span.End()

	require.True(t, span.SpanContext().IsSampled(),
		"AlwaysSampled must force sampling even under a valid, unsampled real parent")
}

// TestStartMessageSpan_NotAlwaysSampledClearsRealParent covers the existing direction: a
// sampled real parent must not force-sample a child that didn't ask for AlwaysSampled.
func TestStartMessageSpan_NotAlwaysSampledClearsRealParent(t *testing.T) {
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0))))
	defer func() { _ = tp.Shutdown(context.Background()) }()
	tr := NewTracing(tp.Tracer("test"))

	sampledParent := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID: oteltrace.TraceID{0x02}, SpanID: oteltrace.SpanID{0x02},
		TraceFlags: oteltrace.FlagsSampled,
	})
	ctx := oteltrace.ContextWithSpanContext(context.Background(), sampledParent)

	_, span := tr.StartMessageSpan(ctx, "child", protocol.Bytes32{}, WithAttributes("k", "v"))
	defer span.End()

	require.False(t, span.SpanContext().IsSampled(),
		"a reused sampled real parent must not force-sample a span that didn't ask for AlwaysSampled")
}
