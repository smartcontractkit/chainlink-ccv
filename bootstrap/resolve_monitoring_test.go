package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestResolveMonitoring(t *testing.T) {
	fallback := monitoring.Config{Enabled: true, Type: "beholder"}

	t.Run("nil bootstrap config falls back to app config", func(t *testing.T) {
		got := ResolveMonitoring(logger.Test(t), nil, fallback)
		require.Equal(t, fallback, got)
	})

	t.Run("bootstrap config wins over app config", func(t *testing.T) {
		fromBootstrap := &monitoring.Config{Enabled: true, Type: "noop"}
		got := ResolveMonitoring(logger.Test(t), fromBootstrap, fallback)
		require.Equal(t, *fromBootstrap, got)
		require.NotEqual(t, fallback, got, "deprecated app-config value must be ignored when bootstrap config is present")
	})

	t.Run("explicit disable in bootstrap config is honored, not overridden by fallback", func(t *testing.T) {
		// An operator who sets [monitoring] with Enabled=false must get monitoring off,
		// even when the deprecated app-config value is enabled.
		fromBootstrap := &monitoring.Config{Enabled: false}
		got := ResolveMonitoring(logger.Test(t), fromBootstrap, fallback)
		require.False(t, got.Enabled)
	})
}
