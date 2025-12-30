package monitoring

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

var _ verifier.Monitoring = (*VerifierBeholderMonitoring)(nil)

// VerifierBeholderMonitoring provides beholder-based monitoring for the verifier.
type VerifierBeholderMonitoring struct {
	metrics verifier.MetricLabeler
}

// InitMonitoring initializes the beholder monitoring system for the verifier.
func InitMonitoring() (verifier.Monitoring, error) {
	// Initialize the verifier metrics
	verifierMetrics, err := InitMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize verifier metrics: %w", err)
	}

	return &VerifierBeholderMonitoring{
		metrics: NewVerifierMetricLabeler(metrics.NewLabeler(), verifierMetrics),
	}, nil
}

func (v *VerifierBeholderMonitoring) Metrics() verifier.MetricLabeler {
	return v.metrics
}

var (
	_ verifier.Monitoring    = (*FakeVerifierMonitoring)(nil)
	_ verifier.MetricLabeler = (*FakeVerifierMetricLabeler)(nil)
)

type FakeVerifierMonitoring struct {
	Fake *FakeVerifierMetricLabeler
}

func (f FakeVerifierMonitoring) Metrics() verifier.MetricLabeler {
	return f.Fake
}

func NewFakeVerifierMonitoring() *FakeVerifierMonitoring {
	return &FakeVerifierMonitoring{
		Fake: &FakeVerifierMetricLabeler{},
	}
}

type FakeVerifierMetricLabeler struct {
	mu     sync.RWMutex
	labels []string

	SourceChainLatestBLock    atomic.Int64
	SourceChainFinalizedBlock atomic.Int64

	E2ELatencyCalls []E2ELatencyCall
}

type E2ELatencyCall struct {
	Labels  []string
	Latency time.Duration
}

func (f *FakeVerifierMetricLabeler) Labels() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.labels
}

func (f *FakeVerifierMetricLabeler) With(keyValues ...string) verifier.MetricLabeler {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.labels = keyValues
	return f
}

func (f *FakeVerifierMetricLabeler) RecordMessageE2ELatency(_ context.Context, latency time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.E2ELatencyCalls = append(f.E2ELatencyCalls, E2ELatencyCall{
		Labels:  append([]string(nil), f.labels...),
		Latency: latency,
	})
}

func (f *FakeVerifierMetricLabeler) IncrementMessagesProcessed(context.Context) {}

func (f *FakeVerifierMetricLabeler) IncrementMessagesVerificationFailed(context.Context) {}

func (f *FakeVerifierMetricLabeler) RecordFinalityWaitDuration(context.Context, time.Duration) {}

func (f *FakeVerifierMetricLabeler) RecordMessageVerificationDuration(context.Context, time.Duration) {
}

func (f *FakeVerifierMetricLabeler) RecordStorageWriteDuration(context.Context, time.Duration) {}

func (f *FakeVerifierMetricLabeler) RecordFinalityQueueSize(context.Context, int64) {}

func (f *FakeVerifierMetricLabeler) RecordCCVDataChannelSize(context.Context, int64) {}

func (f *FakeVerifierMetricLabeler) IncrementStorageWriteErrors(context.Context) {}

func (f *FakeVerifierMetricLabeler) RecordSourceChainLatestBlock(_ context.Context, blockNum int64) {
	f.SourceChainLatestBLock.Store(blockNum)
}

func (f *FakeVerifierMetricLabeler) RecordSourceChainFinalizedBlock(_ context.Context, blockNum int64) {
	f.SourceChainFinalizedBlock.Store(blockNum)
}

func (f *FakeVerifierMetricLabeler) RecordReorgTrackedSeqNums(context.Context, int64) {}
