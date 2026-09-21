package testutil

import (
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"

	commontracing "github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
)

// StubTracing stubs MockAggregatorMonitoring.Tracing() with a real Tracing backed by
// beholder's global (no-op until a beholder client is set) tracer, so tests exercising
// code paths that open spans don't need to hand-roll a tracing expectation.
func StubTracing(mon *mocks.MockAggregatorMonitoring) {
	mon.EXPECT().Tracing().Return(commontracing.NewTracing(beholder.GetTracer())).Maybe()
}
