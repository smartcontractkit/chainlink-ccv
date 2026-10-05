package verifier

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
)

const (
	solanaDevnetSelector = protocol.ChainSelector(16423721717087811551)
	sepoliaSelector      = protocol.ChainSelector(16015286601757825753)
)

func TestCreateSourceConfigs_DisableFinalityChecker(t *testing.T) {
	verifiers := map[protocol.ChainSelector]protocol.UnknownAddress{
		solanaDevnetSelector: {0x01},
		sepoliaSelector:      {0x02},
	}

	t.Run("disabled only for the listed selector", func(t *testing.T) {
		got := createSourceConfigs(verifiers, []string{"16423721717087811551"})
		require.True(t, got[solanaDevnetSelector].DisableFinalityChecker)
		require.False(t, got[sepoliaSelector].DisableFinalityChecker)
	})

	t.Run("enabled everywhere when the list is empty", func(t *testing.T) {
		for _, list := range [][]string{nil, {}} {
			got := createSourceConfigs(verifiers, list)
			require.False(t, got[solanaDevnetSelector].DisableFinalityChecker)
			require.False(t, got[sepoliaSelector].DisableFinalityChecker)
		}
	})
}

// App config decodes strictly, so an unknown key is a startup failure, not a silent no-op.
func TestTokenConfig_DisableFinalityCheckersDecodesFromTOML(t *testing.T) {
	var cfg token.Config
	md, err := toml.Decode(`
disable_finality_checkers = ["16423721717087811551"]

[on_ramp_addresses]
16423721717087811551 = "0xac97"
`, &cfg)
	require.NoError(t, err)
	require.Empty(t, md.Undecoded())
	require.Equal(t, []string{"16423721717087811551"}, cfg.DisableFinalityCheckers)
}
