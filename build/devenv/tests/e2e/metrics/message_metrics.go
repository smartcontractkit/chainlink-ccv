package metrics

import (
	"slices"
	"testing"
	"time"
)

type MessageMetrics struct {
	SeqNo           uint64
	MessageID       string
	SentTime        time.Time
	ExecutedTime    time.Time
	LatencyDuration time.Duration
	// LogAsserter metrics
	VerifierReachedTime       time.Time
	FirstVerifierSignTime     time.Time
	ExecutorProcessingTime    time.Time
	SentToChainInExecutorTime time.Time
	VerifierToExecutorLatency time.Duration
}

// PercentileStats holds common percentile values for a set of durations.
type PercentileStats struct {
	Min time.Duration
	Max time.Duration
	P90 time.Duration
	P95 time.Duration
	P99 time.Duration
}

// MessageTotals holds count totals for message processing.
type MessageTotals struct {
	Sent                  int
	ReachedVerifier       int
	Verified              int
	Aggregated            int
	Indexed               int
	ReachedExecutor       int
	SentToChainInExecutor int
	Received              int
	// Maps for tracking specific messages
	SentMessages                  map[uint64]string // seqNo -> messageID
	ReachedVerifierMessages       map[uint64]string // seqNo -> messageID
	VerifiedMessages              map[uint64]string // seqNo -> messageID
	AggregatedMessages            map[uint64]string // seqNo -> messageID
	IndexedMessages               map[uint64]string // seqNo -> messageID
	ReachedExecutorMessages       map[uint64]string // seqNo -> messageID
	SentToChainInExecutorMessages map[uint64]string // seqNo -> messageID
	ReceivedMessages              map[uint64]string // seqNo -> messageID
}

// MetricsSummary holds aggregate metrics for all messages.
type MetricsSummary struct {
	TotalSent                  int
	TotalReachedVerifier       int
	TotalVerified              int
	TotalAggregated            int
	TotalIndexed               int
	TotalReachedExecutor       int
	TotalSentToChainInExecutor int
	TotalReceived              int
	MinLatency                 time.Duration
	MaxLatency                 time.Duration
	P90Latency                 time.Duration
	P95Latency                 time.Duration
	P99Latency                 time.Duration
	// LogAsserter pipeline metrics
	MinVerifierToExecutor time.Duration
	MaxVerifierToExecutor time.Duration
	P90VerifierToExecutor time.Duration
	P95VerifierToExecutor time.Duration
	P99VerifierToExecutor time.Duration
	// Maps for detailed reporting
	SentMessages                  map[uint64]string
	ReachedVerifierMessages       map[uint64]string
	VerifiedMessages              map[uint64]string
	AggregatedMessages            map[uint64]string
	IndexedMessages               map[uint64]string
	ReachedExecutorMessages       map[uint64]string
	SentToChainInExecutorMessages map[uint64]string
	ReceivedMessages              map[uint64]string
}

// calculatePercentiles computes percentile statistics from a slice of durations.
// The input slice will be sorted in place.
func calculatePercentiles(durations []time.Duration) PercentileStats {
	if len(durations) == 0 {
		return PercentileStats{}
	}

	slices.Sort(durations)

	p90Index := int(float64(len(durations)) * 0.90)
	p95Index := int(float64(len(durations)) * 0.95)
	p99Index := int(float64(len(durations)) * 0.99)

	if p90Index >= len(durations) {
		p90Index = len(durations) - 1
	}
	if p95Index >= len(durations) {
		p95Index = len(durations) - 1
	}
	if p99Index >= len(durations) {
		p99Index = len(durations) - 1
	}

	return PercentileStats{
		Min: durations[0],
		Max: durations[len(durations)-1],
		P90: durations[p90Index],
		P95: durations[p95Index],
		P99: durations[p99Index],
	}
}

// calculateMetricsSummary computes aggregate statistics from message metrics.
func CalculateMetricsSummary(metrics []MessageMetrics, totals MessageTotals) MetricsSummary {
	summary := MetricsSummary{
		TotalSent:                     totals.Sent,
		TotalReachedVerifier:          totals.ReachedVerifier,
		TotalVerified:                 totals.Verified,
		TotalAggregated:               totals.Aggregated,
		TotalIndexed:                  totals.Indexed,
		TotalReachedExecutor:          totals.ReachedExecutor,
		TotalSentToChainInExecutor:    totals.SentToChainInExecutor,
		TotalReceived:                 totals.Received,
		SentMessages:                  totals.SentMessages,
		ReachedVerifierMessages:       totals.ReachedVerifierMessages,
		VerifiedMessages:              totals.VerifiedMessages,
		AggregatedMessages:            totals.AggregatedMessages,
		IndexedMessages:               totals.IndexedMessages,
		ReachedExecutorMessages:       totals.ReachedExecutorMessages,
		SentToChainInExecutorMessages: totals.SentToChainInExecutorMessages,
		ReceivedMessages:              totals.ReceivedMessages,
	}

	if len(metrics) == 0 {
		return summary
	}

	// Extract latencies for end-to-end metrics
	latencies := make([]time.Duration, len(metrics))
	for i, m := range metrics {
		latencies[i] = m.LatencyDuration
	}

	// Calculate end-to-end percentiles
	endToEndStats := calculatePercentiles(latencies)
	summary.MinLatency = endToEndStats.Min
	summary.MaxLatency = endToEndStats.Max
	summary.P90Latency = endToEndStats.P90
	summary.P95Latency = endToEndStats.P95
	summary.P99Latency = endToEndStats.P99

	// Extract verifier-to-executor latencies
	verifierToExecutorLatencies := make([]time.Duration, 0)
	for _, m := range metrics {
		if m.VerifierToExecutorLatency > 0 {
			verifierToExecutorLatencies = append(verifierToExecutorLatencies, m.VerifierToExecutorLatency)
		}
	}

	// Calculate verifier-to-executor percentiles
	if len(verifierToExecutorLatencies) > 0 {
		pipelineStats := calculatePercentiles(verifierToExecutorLatencies)
		summary.MinVerifierToExecutor = pipelineStats.Min
		summary.MaxVerifierToExecutor = pipelineStats.Max
		summary.P90VerifierToExecutor = pipelineStats.P90
		summary.P95VerifierToExecutor = pipelineStats.P95
		summary.P99VerifierToExecutor = pipelineStats.P99
	}

	return summary
}

// printMetricsSummary outputs message timing metrics in a readable format.
func PrintMetricsSummary(t *testing.T, summary MetricsSummary) {
	successRate := 0.0
	if summary.TotalSent > 0 {
		successRate = float64(summary.TotalReceived) / float64(summary.TotalSent) * 100
	}

	t.Logf("\n"+
		"========================================\n"+
		"         Message Timing Metrics        \n"+
		"========================================\n"+
		"Total Sent:             %d\n"+
		"Received (Executed):    %d\n"+
		"Success Rate:           %.2f%%\n"+
		"----------------------------------------\n"+
		"End-to-End Latency (Sent → Executed):\n"+
		"  Min:           %v\n"+
		"  Max:           %v\n"+
		"  P90:           %v\n"+
		"  P95:           %v\n"+
		"  P99:           %v\n",
		summary.TotalSent,
		summary.TotalReceived,
		successRate,
		summary.MinLatency,
		summary.MaxLatency,
		summary.P90Latency,
		summary.P95Latency,
		summary.P99Latency,
	)
}
