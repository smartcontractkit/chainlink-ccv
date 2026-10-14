package jobs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestJDInfrastructureConnectTimeout(t *testing.T) {
	t.Run("default when unset", func(t *testing.T) {
		require.Equal(t, DefaultNodeConnectTimeout, (&JDInfrastructure{}).ConnectTimeout())
	})

	t.Run("default when infra is nil", func(t *testing.T) {
		var infra *JDInfrastructure
		require.Equal(t, DefaultNodeConnectTimeout, infra.ConnectTimeout())
	})

	t.Run("override via node_connect_timeout", func(t *testing.T) {
		infra := &JDInfrastructure{NodeConnectTimeout: "5m"}
		require.Equal(t, 5*time.Minute, infra.ConnectTimeout())
	})

	t.Run("sub-minute override", func(t *testing.T) {
		infra := &JDInfrastructure{NodeConnectTimeout: "10s"}
		require.Equal(t, 10*time.Second, infra.ConnectTimeout())
	})

	t.Run("invalid duration falls back to default", func(t *testing.T) {
		infra := &JDInfrastructure{NodeConnectTimeout: "bogus"}
		require.Equal(t, DefaultNodeConnectTimeout, infra.ConnectTimeout())
	})

	t.Run("non-positive duration falls back to default", func(t *testing.T) {
		infra := &JDInfrastructure{NodeConnectTimeout: "0s"}
		require.Equal(t, DefaultNodeConnectTimeout, infra.ConnectTimeout())
	})
}
