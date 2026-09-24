package evmconfig

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

const roundTripSelector = "16015286601757825753"

// Generated configs (devenv, migration tooling) go Info -> Config -> TOML, so a dropped field
// silently resets the chain to its default.
func TestNewConfigFromInfosKeepsLogPollerMode(t *testing.T) {
	t.Parallel()

	cfg := NewConfigFromInfos(chainaccess.Infos[Info]{
		roundTripSelector: {LogPollerMode: LogPollerModeRead},
	})
	require.Equal(t, LogPollerMode(LogPollerModeRead), cfg.Chains[roundTripSelector].LogPollerMode)

	infos, err := cfg.ToInfos()
	require.NoError(t, err)
	require.Equal(t, LogPollerMode(LogPollerModeRead), infos[roundTripSelector].LogPollerMode)
}

func TestNewConfigFromInfosOmitsUnsetLogPollerMode(t *testing.T) {
	t.Parallel()

	out, err := toml.Marshal(NewConfigFromInfos(chainaccess.Infos[Info]{roundTripSelector: {}}))
	require.NoError(t, err)
	require.NotContains(t, string(out), "log_poller_mode")
}
