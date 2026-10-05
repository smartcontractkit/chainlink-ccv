package monitoring

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
)

// restoreBeholderClient swaps the global beholder client back after the test. SetupBeholder
// replaces it, and other packages' tests may observe the global.
func restoreBeholderClient(t *testing.T) {
	t.Helper()
	prev := beholder.GetClient()
	t.Cleanup(func() {
		// Best-effort shutdown of the OTel providers a client created by the test spun up; the
		// pre-existing global (typically the shared noop client) is left running.
		if cur := beholder.GetClient(); cur != prev {
			_ = cur.Close()
		}
		beholder.SetClient(prev)
	})
}

func TestSetupBeholderWiresChipIngress(t *testing.T) {
	restoreBeholderClient(t)

	err := SetupBeholder(BeholderConfig{
		Enabled:                       true,
		InsecureConnection:            true,
		OtelExporterGRPCEndpoint:      "localhost:4317",
		ChipIngressEndpoint:           "chip-ingress:9090",
		ChipIngressInsecureConnection: true,
		MetricReaderInterval:          5,
		TraceSampleRatio:              1,
		TraceBatchTimeout:             5,
	}, nil, nil)
	require.NoError(t, err)

	cfg := beholder.GetClient().Config
	require.True(t, cfg.ChipIngressEmitterEnabled)
	require.Equal(t, "chip-ingress:9090", cfg.ChipIngressEmitterGRPCEndpoint)
	require.True(t, cfg.ChipIngressInsecureConnection)
}

func TestSetupBeholderLeavesChipIngressDisabledWithoutEndpoint(t *testing.T) {
	restoreBeholderClient(t)

	err := SetupBeholder(BeholderConfig{
		Enabled:                  true,
		InsecureConnection:       true,
		OtelExporterGRPCEndpoint: "localhost:4317",
		MetricReaderInterval:     5,
		TraceSampleRatio:         1,
		TraceBatchTimeout:        5,
	}, nil, nil)
	require.NoError(t, err)

	cfg := beholder.GetClient().Config
	require.False(t, cfg.ChipIngressEmitterEnabled)
	require.Empty(t, cfg.ChipIngressEmitterGRPCEndpoint)
}

func TestSetupBeholderDisabledKeepsGlobalClient(t *testing.T) {
	restoreBeholderClient(t)

	prev := beholder.GetClient()
	require.NoError(t, SetupBeholder(BeholderConfig{Enabled: false, ChipIngressEndpoint: "chip-ingress:9090"}, nil, nil))
	require.Same(t, prev, beholder.GetClient())
}
