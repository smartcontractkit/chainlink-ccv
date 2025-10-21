package metrics

import (
	"sort"
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
	FirstVerifierSignTime     time.Time
	ExecutorProcessingTime    time.Time
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
	Sent       int
	Aggregated int
	Indexed    int
	Received   int
	// Maps for tracking specific messages
	SentMessages       map[uint64]string // seqNo -> messageID
	AggregatedMessages map[uint64]string // seqNo -> messageID
	IndexedMessages    map[uint64]string // seqNo -> messageID
	ReceivedMessages   map[uint64]string // seqNo -> messageID
}

// MetricsSummary holds aggregate metrics for all messages.
type MetricsSummary struct {
	TotalSent       int
	TotalAggregated int
	TotalIndexed    int
	TotalReceived   int
	MinLatency      time.Duration
	MaxLatency      time.Duration
	P90Latency      time.Duration
	P95Latency      time.Duration
	P99Latency      time.Duration
	// LogAsserter pipeline metrics
	MinVerifierToExecutor time.Duration
	MaxVerifierToExecutor time.Duration
	P90VerifierToExecutor time.Duration
	P95VerifierToExecutor time.Duration
	P99VerifierToExecutor time.Duration
	// Maps for detailed reporting
	SentMessages       map[uint64]string
	AggregatedMessages map[uint64]string
	IndexedMessages    map[uint64]string
	ReceivedMessages   map[uint64]string
}

// calculatePercentiles computes percentile statistics from a slice of durations.
// The input slice will be sorted in place.
func calculatePercentiles(durations []time.Duration) PercentileStats {
	if len(durations) == 0 {
		return PercentileStats{}
	}

	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})

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
		TotalSent:          totals.Sent,
		TotalAggregated:    totals.Aggregated,
		TotalIndexed:       totals.Indexed,
		TotalReceived:      totals.Received,
		SentMessages:       totals.SentMessages,
		AggregatedMessages: totals.AggregatedMessages,
		IndexedMessages:    totals.IndexedMessages,
		ReceivedMessages:   totals.ReceivedMessages,
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
		"Total Sent:      %d\n"+
		"Aggregated:      %d\n"+
		"Indexed:         %d\n"+
		"Received:        %d\n"+
		"Success Rate:    %.2f%%\n"+
		"----------------------------------------\n"+
		"End-to-End Latency (Sent → Executed):\n"+
		"  Min:           %v\n"+
		"  Max:           %v\n"+
		"  P90:           %v\n"+
		"  P95:           %v\n"+
		"  P99:           %v\n",
		summary.TotalSent,
		summary.TotalAggregated,
		summary.TotalIndexed,
		summary.TotalReceived,
		successRate,
		summary.MinLatency,
		summary.MaxLatency,
		summary.P90Latency,
		summary.P95Latency,
		summary.P99Latency,
	)

	// Print verifier-to-executor metrics if available
	if summary.MinVerifierToExecutor > 0 {
		t.Logf("----------------------------------------\n"+
			"Pipeline Latency (First Verifier → Executor):\n"+
			"  Min:           %v\n"+
			"  Max:           %v\n"+
			"  P90:           %v\n"+
			"  P95:           %v\n"+
			"  P99:           %v\n"+
			"========================================",
			summary.MinVerifierToExecutor,
			summary.MaxVerifierToExecutor,
			summary.P90VerifierToExecutor,
			summary.P95VerifierToExecutor,
			summary.P99VerifierToExecutor,
		)
	} else {
		t.Logf("========================================")
	}

	// Find messages that were sent but not aggregated
	notAggregated := make(map[uint64]string)
	for seqNo, msgID := range summary.SentMessages {
		if _, aggregated := summary.AggregatedMessages[seqNo]; !aggregated {
			notAggregated[seqNo] = msgID
		}
	}

	// Find messages that were sent but not indexed
	notIndexed := make(map[uint64]string)
	for seqNo, msgID := range summary.SentMessages {
		if _, indexed := summary.IndexedMessages[seqNo]; !indexed {
			notIndexed[seqNo] = msgID
		}
	}

	// Find messages that were indexed but not received
	indexedNotReceived := make(map[uint64]string)
	for seqNo, msgID := range summary.IndexedMessages {
		if _, received := summary.ReceivedMessages[seqNo]; !received {
			indexedNotReceived[seqNo] = msgID
		}
	}

	// Print detailed failure information
	if len(notAggregated) > 0 {
		t.Logf("\n========================================")
		t.Logf("Messages NOT Aggregated (%d):", len(notAggregated))
		t.Logf("========================================")
		seqNos := make([]uint64, 0, len(notAggregated))
		for seqNo := range notAggregated {
			seqNos = append(seqNos, seqNo)
		}
		sort.Slice(seqNos, func(i, j int) bool { return seqNos[i] < seqNos[j] })
		for _, seqNo := range seqNos {
			t.Logf("  SeqNo: %d, MessageID: %s", seqNo, notAggregated[seqNo])
		}
	}

	if len(notIndexed) > 0 {
		t.Logf("\n========================================")
		t.Logf("Messages NOT Indexed (%d):", len(notIndexed))
		t.Logf("========================================")
		// Sort by seqNo for consistent output
		seqNos := make([]uint64, 0, len(notIndexed))
		for seqNo := range notIndexed {
			seqNos = append(seqNos, seqNo)
		}
		sort.Slice(seqNos, func(i, j int) bool { return seqNos[i] < seqNos[j] })
		for _, seqNo := range seqNos {
			t.Logf("  SeqNo: %d, MessageID: %s", seqNo, notIndexed[seqNo])
		}
	}

	if len(indexedNotReceived) > 0 {
		t.Logf("\n========================================")
		t.Logf("Messages Indexed but NOT Received (%d):", len(indexedNotReceived))
		t.Logf("========================================")
		// Sort by seqNo for consistent output
		seqNos := make([]uint64, 0, len(indexedNotReceived))
		for seqNo := range indexedNotReceived {
			seqNos = append(seqNos, seqNo)
		}
		sort.Slice(seqNos, func(i, j int) bool { return seqNos[i] < seqNos[j] })
		for _, seqNo := range seqNos {
			t.Logf("  SeqNo: %d, MessageID: %s", seqNo, indexedNotReceived[seqNo])
		}
	}
}
