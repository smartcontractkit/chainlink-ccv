package ccv

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// env-log-poller.toml restates env.toml's verifier array, so it must stay identical to it apart
// from log_poller_mode, or verifiers silently drift or disappear under standard.log-poller.profile.
func TestLogPollerOverlayMatchesBaseVerifiers(t *testing.T) {
	base, err := Load[Cfg]([]string{"env.toml"})
	require.NoError(t, err)
	merged, err := Load[Cfg]([]string{"env.toml", "env-log-poller.toml"})
	require.NoError(t, err)

	require.Len(t, merged.Verifier, len(base.Verifier))
	modes := map[string]string{}
	for i, v := range merged.Verifier {
		modes[v.ContainerName] = v.LogPollerMode
		withoutMode := *v
		withoutMode.LogPollerMode = ""
		require.Equal(t, *base.Verifier[i], withoutMode, v.ContainerName)
	}
	require.Equal(t, map[string]string{
		"default-verifier-1":   "read",
		"default-verifier-2":   "",
		"secondary-verifier-1": "shadow",
		"secondary-verifier-2": "",
		"tertiary-verifier-1":  "",
		"tertiary-verifier-2":  "",
	}, modes)
}
