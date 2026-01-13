package load

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-testing-framework/wasp"
)

type MetricsSummary struct {
	TotalSent     int64
	TotalVerified int64
}

func createLoadProfile(rps int64, testDuration time.Duration) (*wasp.Profile, *IndexerLoadGun, error) {
	gun, err := NewIndexerLoadGun()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create load profile: %w", err)
	}

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
	return profile, gun, nil
}

func TestIndexerLoad(t *testing.T) {
	rps := int64(50)
	testDuration := 1 * time.Minute

	p, gun, err := createLoadProfile(rps, testDuration)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), testDuration*2)
	defer cancel()

	verifyDoneCh := gun.VerifyMessagesAsync(ctx)
	_, err = p.Run(true)
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

	summary.TotalSent = sent
	summary.TotalVerified = int64(len(metrics))

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
		"----------------------------------------\n",
		summary.TotalSent,
		summary.TotalVerified,
		summary.TotalSent-summary.TotalVerified,
		float64(summary.TotalVerified)/float64(summary.TotalSent)*100,
	)
}
