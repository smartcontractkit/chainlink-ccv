package scope

import (
	"context"
	"testing"

	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	aggregation_mocks "github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
)

func TestWithContextHelpers_RoundTrip(t *testing.T) {
	// Table of setters and context keys to check presence (via AugmentMetrics expectations)
	ctx := context.Background()
	ctx = WithAPIName(ctx, "GetMessages")
	ctx = WithRequestID(ctx)
	ctx = WithMessageID(ctx, []byte{0x01, 0x02})
	ctx = WithAddress(ctx, []byte{0xab, 0xcd})
	ctx = WithParticipantID(ctx, "participant")
	ctx = WithCommitteeID(ctx, "committee-1")

	// Ensure AugmentMetrics applies expected labels
	mockLabeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
	// Order is committeeID then apiName (see metricsContextKeys)
	mockLabeler.EXPECT().With("committeeID", "committee-1").Return(mockLabeler)
	mockLabeler.EXPECT().With("apiName", "GetMessages").Return(mockLabeler)

	_ = AugmentMetrics(ctx, mockLabeler)
}

func TestAugmentLogger_NoPanicAndCoversIdentity(t *testing.T) {
	ctx := context.Background()
	ctx = WithAPIName(ctx, "Read")
	ctx = WithMessageID(ctx, []byte{0x0})
	ctx = WithAddress(ctx, []byte{0x1})
	ctx = WithParticipantID(ctx, "p")
	ctx = WithCommitteeID(ctx, "c")

	// Add identity to hit the identity branch in AugmentLogger
	id := auth.CreateCallerIdentity("caller-123", false)
	ctx = auth.ToContext(ctx, id)

	// Use a no-op logger via mocks by relying on the interface behavior: we only ensure no panic.
	// We can't easily introspect fields; just ensure call is safe.
	// Create a simple logger using chainlink-common would require full zap plumbing; avoid here.
	// Instead, use a nil-safe approach by passing a no-op SugaredLogger (zero-value not available),
	// so we leverage the fact that AugmentLogger only calls .With and returns it; we don't log.
	// For coverage, just ensure the function executes without panic.
	// We'll reuse the labeler mock type to satisfy logging expectations isn't possible; so we skip assertions.
	// Hence we import the package-level logger through a tiny adapter if needed; but not necessary for coverage.

	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	sugared := logger.Sugared(lggr)
	l := AugmentLogger(ctx, sugared)
	l.Infof("smoke")
}
