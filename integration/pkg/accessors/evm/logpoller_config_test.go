package evm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Both deployment paths build their reader config through NewLogPollerConfig, so they share this retention.
func TestNewLogPollerConfig(t *testing.T) {
	t.Parallel()
	cfg := NewLogPollerConfig(nil, "verifier-1")
	require.Equal(t, DefaultMessageSentLogRetention, cfg.Retention)
}
