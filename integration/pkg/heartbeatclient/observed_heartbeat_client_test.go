package heartbeatclient_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestObservedHeartbeatClient_Close(t *testing.T) {
	lggr := logger.Test(t)
	fakeMonitoring := monitoring.NewFakeVerifierMonitoring()

	delegateClient := &heartbeatclient.HeartbeatClient{}

	observedClient := heartbeatclient.NewObservedHeartbeatClient(
		delegateClient,
		"test-verifier",
		lggr,
		fakeMonitoring,
	)

	// Close should not error
	err := observedClient.Close()
	assert.NoError(t, err)
}

func TestObservedHeartbeatClient_FakeMonitoring(t *testing.T) {
	lggr := logger.Test(t)
	ctx := context.Background()

	// Use real FakeVerifierMonitoring to test integration
	fakeMonitoring := monitoring.NewFakeVerifierMonitoring()

	delegateClient := &heartbeatclient.HeartbeatClient{}
	observedClient := heartbeatclient.NewObservedHeartbeatClient(
		delegateClient,
		"test-verifier",
		lggr,
		fakeMonitoring,
	)
	require.NotNil(t, observedClient)

	// These should not panic with real monitoring
	metrics := fakeMonitoring.Metrics()
	assert.NotNil(t, metrics)

	// Verify we can call metric methods without error
	metrics.RecordHeartbeatDuration(ctx, 100*time.Millisecond)
	metrics.IncrementHeartbeatsSent(ctx)
	metrics.IncrementHeartbeatsFailed(ctx)
	metrics.SetVerifierHeartbeatTimestamp(ctx, time.Now().Unix())
	metrics.SetVerifierHeartbeatSentChainHeads(ctx, 100)
	metrics.SetVerifierHeartbeatChainHeads(ctx, 200)
	metrics.SetVerifierHeartbeatScore(ctx, 0.95)
}

func TestObservedHeartbeatClient_WithChainSelector(t *testing.T) {
	lggr := logger.Test(t)

	// Use real FakeVerifierMonitoring, following the codebase pattern
	fakeMonitoring := monitoring.NewFakeVerifierMonitoring()

	delegateClient := &heartbeatclient.HeartbeatClient{}

	observedClient := heartbeatclient.NewObservedHeartbeatClient(
		delegateClient,
		"test-verifier",
		lggr,
		fakeMonitoring,
	)
	require.NotNil(t, observedClient)

	metrics := fakeMonitoring.Metrics()

	// Verify that With() returns a metric labeler that can be used for chain-specific metrics
	chainMetrics := metrics.With("chain_selector", "42")
	assert.NotNil(t, chainMetrics)

	chainMetrics = metrics.With("chain_selector", "100")
	assert.NotNil(t, chainMetrics)
}
