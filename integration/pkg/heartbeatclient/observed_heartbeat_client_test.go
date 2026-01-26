package heartbeatclient_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
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
		verifier.NewHeartbeatMonitoringAdapter(fakeMonitoring),
	)

	// Close should not error
	err := observedClient.Close()
	assert.NoError(t, err)
}

func TestObservedHeartbeatClient_WithChainSelector(t *testing.T) {
	lggr := logger.Test(t)
	fakeMonitoring := monitoring.NewFakeVerifierMonitoring()

	delegateClient := &heartbeatclient.HeartbeatClient{}

	observedClient := heartbeatclient.NewObservedHeartbeatClient(
		delegateClient,
		"test-verifier",
		lggr,
		verifier.NewHeartbeatMonitoringAdapter(fakeMonitoring),
	)
	require.NotNil(t, observedClient)

	metrics := fakeMonitoring.Metrics()

	// Verify that With() returns a metric labeler that can be used for chain-specific metrics
	chainMetrics := metrics.With("chain_selector", "42")
	assert.NotNil(t, chainMetrics)

	chainMetrics = metrics.With("chain_selector", "100")
	assert.NotNil(t, chainMetrics)
}
