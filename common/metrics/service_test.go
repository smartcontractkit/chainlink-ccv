package metrics_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	commonmetrics "github.com/smartcontractkit/chainlink-ccv/common/metrics"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

func TestServiceMetrics_RecordServiceStartedAndChainHealthy(t *testing.T) {
	protocol.InitChainSelectorCache()

	sm, err := commonmetrics.NewServiceMetrics(metrics.NewLabeler(), "committee_verifier")
	require.NoError(t, err)
	require.NotNil(t, sm)

	ctx := context.Background()
	require.NotPanics(t, func() {
		sm.RecordServiceStarted(ctx)
	})

	const (
		goodSelector protocol.ChainSelector = 5009297550715157269
		badSelector  protocol.ChainSelector = 3478487238524512106
	)

	require.NotPanics(t, func() {
		sm.RecordChainHealthy(ctx, goodSelector, true)
		sm.RecordChainHealthy(ctx, badSelector, false)
	})
}
