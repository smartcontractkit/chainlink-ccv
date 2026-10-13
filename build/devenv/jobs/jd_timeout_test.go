package jobs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNodeConnectTimeout(t *testing.T) {
	t.Run("default when unset", func(t *testing.T) {
		require.Equal(t, DefaultNodeConnectTimeout, NodeConnectTimeout())
	})

	t.Run("override via env var", func(t *testing.T) {
		t.Setenv(EnvVarNodeConnectTimeout, "5m")
		require.Equal(t, 5*time.Minute, NodeConnectTimeout())
	})

	t.Run("sub-minute override", func(t *testing.T) {
		t.Setenv(EnvVarNodeConnectTimeout, "10s")
		require.Equal(t, 10*time.Second, NodeConnectTimeout())
	})

	t.Run("invalid duration falls back to default", func(t *testing.T) {
		t.Setenv(EnvVarNodeConnectTimeout, "bogus")
		require.Equal(t, DefaultNodeConnectTimeout, NodeConnectTimeout())
	})

	t.Run("non-positive duration falls back to default", func(t *testing.T) {
		t.Setenv(EnvVarNodeConnectTimeout, "0s")
		require.Equal(t, DefaultNodeConnectTimeout, NodeConnectTimeout())
	})
}
