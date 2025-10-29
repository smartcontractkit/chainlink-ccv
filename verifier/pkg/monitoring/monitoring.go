package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/grafana/pyroscope-go"

	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

var _ verifier.Monitoring = (*VerifierBeholderMonitoring)(nil)

// VerifierBeholderMonitoring provides beholder-based monitoring for the verifier.
type VerifierBeholderMonitoring struct {
	metrics verifier.MetricLabeler
}

// InitMonitoring initializes the beholder monitoring system for the verifier.
func InitMonitoring(config beholder.Config) (verifier.Monitoring, error) {
	// Note: due to OTEL spec, all histogram buckets must be defined when the beholder client is created.
	config.MetricViews = MetricViews()

	// Create the beholder client
	client, err := beholder.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create beholder client: %w", err)
	}

	// Set the beholder client and global otel providers
	beholder.SetClient(client)
	beholder.SetGlobalOtelProviders()

	// Initialize the verifier metrics
	verifierMetrics, err := InitMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize verifier metrics: %w", err)
	}

	// Initialize pyroscope for continuous profiling
	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "verifier",
		ServerAddress:   "http://pyroscope:4040",
		Logger:          pyroscope.StandardLogger,
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileBlockDuration,
			pyroscope.ProfileMutexDuration,
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize pyroscope client: %w", err)
	}

	return &VerifierBeholderMonitoring{
		metrics: NewVerifierMetricLabeler(metrics.NewLabeler(), verifierMetrics),
	}, nil
}

func (v *VerifierBeholderMonitoring) Metrics() verifier.MetricLabeler {
	return v.metrics
}

var _ verifier.Monitoring = (*NoopVerifierMonitoring)(nil)

// NoopVerifierMonitoring provides a no-op implementation of VerifierMonitoring.
type NoopVerifierMonitoring struct {
	noop verifier.MetricLabeler
}

// NewNoopVerifierMonitoring creates a new noop monitoring instance.
func NewNoopVerifierMonitoring() verifier.Monitoring {
	return &NoopVerifierMonitoring{
		noop: NewNoopVerifierMetricLabeler(),
	}
}

func (n *NoopVerifierMonitoring) Metrics() verifier.MetricLabeler {
	return n.noop
}

var _ verifier.MetricLabeler = (*NoopVerifierMetricLabeler)(nil)

// NoopVerifierMetricLabeler provides a no-op implementation of VerifierMetricLabeler.
type NoopVerifierMetricLabeler struct{}

// NewNoopVerifierMetricLabeler creates a new noop metric labeler.
func NewNoopVerifierMetricLabeler() verifier.MetricLabeler {
	return &NoopVerifierMetricLabeler{}
}

func (n *NoopVerifierMetricLabeler) With(keyValues ...string) verifier.MetricLabeler {
	return n
}

func (n *NoopVerifierMetricLabeler) RecordMessageE2ELatency(ctx context.Context, duration time.Duration) {
}

func (n *NoopVerifierMetricLabeler) IncrementMessagesProcessed(ctx context.Context) {}

func (n *NoopVerifierMetricLabeler) IncrementMessagesVerificationFailed(ctx context.Context) {}

func (n *NoopVerifierMetricLabeler) RecordFinalityWaitDuration(ctx context.Context, duration time.Duration) {
}

func (n *NoopVerifierMetricLabeler) RecordMessageVerificationDuration(ctx context.Context, duration time.Duration) {
}

func (n *NoopVerifierMetricLabeler) RecordSigningDuration(ctx context.Context, duration time.Duration) {
}

func (n *NoopVerifierMetricLabeler) RecordStorageWriteDuration(ctx context.Context, duration time.Duration) {
}

func (n *NoopVerifierMetricLabeler) RecordFinalityQueueSize(ctx context.Context, size int64) {}

func (n *NoopVerifierMetricLabeler) RecordCCVDataChannelSize(ctx context.Context, size int64) {}

func (n *NoopVerifierMetricLabeler) IncrementStorageWriteErrors(ctx context.Context) {}

func (n *NoopVerifierMetricLabeler) RecordSourceChainLatestBlock(ctx context.Context, blockNum int64) {
}

func (n *NoopVerifierMetricLabeler) RecordSourceChainFinalizedBlock(ctx context.Context, blockNum int64) {
}
