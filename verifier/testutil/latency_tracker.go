package testutil

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

// NoopLatencyTracker is a no-op implementation of verifier.MessageLatencyTracker for use in tests.
type NoopLatencyTracker struct{}

func (n NoopLatencyTracker) MarkMessageAsSeen(*verifier.VerificationTask)                         {}
func (n NoopLatencyTracker) TrackMessageLatencies(context.Context, []protocol.VerifierNodeResult) {}
