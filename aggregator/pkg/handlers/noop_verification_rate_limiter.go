package handlers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// NoopVerificationRateLimiter is a no-op implementation of VerificationRateLimiter that always allows.
type NoopVerificationRateLimiter struct{}

func (NoopVerificationRateLimiter) TryAcquire(_ context.Context, _ *model.CommitVerificationRecord, _ *model.QuorumConfig) (model.TryAcquireResult, error) {
	return model.TryAcquireResult{}, nil
}
