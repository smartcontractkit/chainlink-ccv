package testutil

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

// NoopMetricLabeler is a no-op implementation of verifier.MetricLabeler for use in tests.
type NoopMetricLabeler struct{}

func (n *NoopMetricLabeler) With(_ ...string) verifier.MetricLabeler                              { return n }
func (n *NoopMetricLabeler) RecordMessageE2ELatency(_ context.Context, _ time.Duration)           {}
func (n *NoopMetricLabeler) IncrementMessagesProcessed(_ context.Context)                         {}
func (n *NoopMetricLabeler) IncrementMessagesVerificationFailed(_ context.Context)                {}
func (n *NoopMetricLabeler) RecordMessageVerificationDuration(_ context.Context, _ time.Duration) {}
func (n *NoopMetricLabeler) RecordStorageWriteDuration(_ context.Context, _ time.Duration)        {}
func (n *NoopMetricLabeler) RecordVerificationQueueLatency(_ context.Context, _ time.Duration)    {}
func (n *NoopMetricLabeler) RecordTaskVerificationQueueSize(_ context.Context, _ int64)           {}
func (n *NoopMetricLabeler) RecordStorageWriteQueueSize(_ context.Context, _ int64)               {}
func (n *NoopMetricLabeler) IncrementStorageWriteErrors(_ context.Context)                        {}
func (n *NoopMetricLabeler) IncrementTaskVerificationPermanentErrors(_ context.Context)           {}
func (n *NoopMetricLabeler) IncrementHeartbeatsSent(_ context.Context)                            {}
func (n *NoopMetricLabeler) IncrementHeartbeatsFailed(_ context.Context)                          {}
func (n *NoopMetricLabeler) RecordHeartbeatDuration(_ context.Context, _ time.Duration)           {}
func (n *NoopMetricLabeler) SetVerifierHeartbeatTimestamp(_ context.Context, _ int64)             {}
func (n *NoopMetricLabeler) SetVerifierHeartbeatSentChainHeads(_ context.Context, _ uint64)       {}
func (n *NoopMetricLabeler) SetVerifierHeartbeatChainHeads(_ context.Context, _ uint64)           {}
func (n *NoopMetricLabeler) SetVerifierHeartbeatScore(_ context.Context, _ float64)               {}
func (n *NoopMetricLabeler) RecordSourceChainLatestBlock(_ context.Context, _ int64)              {}
func (n *NoopMetricLabeler) RecordSourceChainFinalizedBlock(_ context.Context, _ int64)           {}
func (n *NoopMetricLabeler) RecordReorgTrackedSeqNums(_ context.Context, _ int64)                 {}
func (n *NoopMetricLabeler) SetVerifierFinalityViolated(_ context.Context, _ protocol.ChainSelector, _ bool) {
}

func (n *NoopMetricLabeler) SetRemoteChainCursed(_ context.Context, _, _ protocol.ChainSelector, _ bool) {
}

func (n *NoopMetricLabeler) SetLocalChainGlobalCursed(_ context.Context, _ protocol.ChainSelector, _ bool) {
}
func (n *NoopMetricLabeler) IncrementActiveRequestsCounter(_ context.Context) {}
func (n *NoopMetricLabeler) IncrementHTTPRequestCounter(_ context.Context)    {}
func (n *NoopMetricLabeler) DecrementActiveRequestsCounter(_ context.Context) {}
func (n *NoopMetricLabeler) RecordHTTPRequestDuration(_ context.Context, _ time.Duration, _, _ string, _ int) {
}

func (n *NoopMetricLabeler) RecordStorageQueryDuration(_ context.Context, _ string, _ time.Duration) {
}
