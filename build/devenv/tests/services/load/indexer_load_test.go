package load

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-testing-framework/wasp"
)

type MetricsSummary struct {
	TotalSent     int64
	TotalVerified int64
	MinLatency    time.Duration
	MaxLatency    time.Duration
	P90Latency    time.Duration
	P95Latency    time.Duration
	P99Latency    time.Duration
}

func createLoadProfile(rps int64, testDuration time.Duration) (*wasp.Profile, *IndexerLoadGun) {
	gun := NewIndexerLoadGun()
	profile := wasp.NewProfile().
		Add(wasp.NewGenerator(&wasp.Config{
			LoadType: wasp.RPS,
			GenName:  "indexer-load-test",
			Schedule: wasp.Combine(
				wasp.Plain(rps, testDuration),
			),
			Gun: gun,
			// Disable Loki config to avoid connection errors
			// LokiConfig: wasp.NewEnvLokiConfig(),
		}))
	return profile, gun
}

func TestIndexerLoad(t *testing.T) {
	rps := int64(100)
	testDuration := 1 * time.Minute

	p, gun := createLoadProfile(rps, testDuration)

	ctx, cancel := context.WithTimeout(context.Background(), testDuration*2)
	defer cancel()

	verifyDoneCh := gun.VerifyMessagesAsync(ctx)
	_, err := p.Run(true)
	require.NoError(t, err)

	// Close the sent message channel to signal no more messages are coming
	gun.CloseSentChannel()

	// Wait for verification to complete
	select {
	case <-verifyDoneCh:
		break
	case <-ctx.Done():
		t.Log("Verification timed out! Not all messages were verified")
	}

	// Collect all metrics from the background verification process
	metrics := gun.Metrics()
	require.NotEmpty(t, metrics)

	summary := calculateMetricsSummary(p.Generators[0].Stats().Success.Load(), metrics)
	printMetricsSummary(t, summary)
}

func calculateMetricsSummary(sent int64, metrics []Metrics) MetricsSummary {
	summary := MetricsSummary{}

	if len(metrics) == 0 {
		return summary
	}

	// Extract and sort latencies
	latencies := make([]time.Duration, len(metrics))
	for i, m := range metrics {
		latencies[i] = m.Latency
	}
	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	// Calculate percentiles
	p90Index := int(float64(len(latencies)) * 0.90)
	p95Index := int(float64(len(latencies)) * 0.95)
	p99Index := int(float64(len(latencies)) * 0.99)

	// Handle edge cases for small sample sizes
	if p90Index >= len(latencies) {
		p90Index = len(latencies) - 1
	}
	if p95Index >= len(latencies) {
		p95Index = len(latencies) - 1
	}
	if p99Index >= len(latencies) {
		p99Index = len(latencies) - 1
	}

	summary.TotalSent = sent
	summary.TotalVerified = int64(len(metrics))
	summary.MinLatency = latencies[0]
	summary.MaxLatency = latencies[len(latencies)-1]
	summary.P90Latency = latencies[p90Index]
	summary.P95Latency = latencies[p95Index]
	summary.P99Latency = latencies[p99Index]

	return summary
}

func printMetricsSummary(t *testing.T, summary MetricsSummary) {
	t.Logf("\n"+
		"========================================\n"+
		"         Message Timing Metrics        \n"+
		"========================================\n"+
		"Total Sent:      %d\n"+
		"Total Verified:  %d\n"+
		"Not Verified:    %d\n"+
		"Success Rate:    %.2f%%\n"+
		"----------------------------------------\n"+
		"Min Latency:     %v\n"+
		"Max Latency:     %v\n"+
		"P90 Latency:     %v\n"+
		"P95 Latency:     %v\n"+
		"P99 Latency:     %v\n"+
		"========================================",
		summary.TotalSent,
		summary.TotalVerified,
		summary.TotalSent-summary.TotalVerified,
		float64(summary.TotalVerified)/float64(summary.TotalSent)*100,
		summary.MinLatency,
		summary.MaxLatency,
		summary.P90Latency,
		summary.P95Latency,
		summary.P99Latency,
	)
}
