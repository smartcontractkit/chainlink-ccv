package blockchains

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func anvilEntry(chainID string) map[string]any {
	return map[string]any{
		"type":           "anvil",
		"chain_id":       chainID,
		"container_name": "anvil-" + chainID,
	}
}

func TestValidateConfig_RejectsNil(t *testing.T) {
	t.Setenv(privateKeyEnvVar, "")
	c := &component{}
	err := c.ValidateConfig(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no [[blockchains]]")
}

func TestValidateConfig_RejectsEmptySlice(t *testing.T) {
	t.Setenv(privateKeyEnvVar, "")
	c := &component{}
	err := c.ValidateConfig([]map[string]any{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no [[blockchains]]")
}

func TestValidateConfig_RejectsUnknownType(t *testing.T) {
	t.Setenv(privateKeyEnvVar, "")
	c := &component{}
	err := c.ValidateConfig([]map[string]any{
		{"type": "not-a-real-type", "chain_id": "1337", "container_name": "x"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "blockchain family")
}

func TestValidateConfig_RejectsAnvilKeyOnRealChain(t *testing.T) {
	t.Setenv(privateKeyEnvVar, "") // empty → networkPrivateKey returns defaultAnvilKey
	c := &component{}
	err := c.ValidateConfig([]map[string]any{anvilEntry("1")})
	require.Error(t, err)
	require.Contains(t, err.Error(), "real chain")
	require.Contains(t, err.Error(), "PRIVATE_KEY")
}

func TestValidateConfig_RejectsRealKeyOnSimChain(t *testing.T) {
	t.Setenv(privateKeyEnvVar, "0x"+
		"1111111111111111111111111111111111111111111111111111111111111111")
	c := &component{}
	err := c.ValidateConfig([]map[string]any{anvilEntry("1337")})
	require.Error(t, err)
	require.Contains(t, err.Error(), "simulated chain")
	require.Contains(t, err.Error(), "PRIVATE_KEY")
}

func TestValidateConfig_AcceptsAnvilOnSimChain(t *testing.T) {
	t.Setenv(privateKeyEnvVar, "")
	c := &component{}
	require.NoError(t, c.ValidateConfig([]map[string]any{anvilEntry("1337")}))
}

func TestValidateConfig_AcceptsMultipleEntries(t *testing.T) {
	t.Setenv(privateKeyEnvVar, "")
	c := &component{}
	require.NoError(t, c.ValidateConfig([]map[string]any{
		anvilEntry("1337"),
		anvilEntry("2337"),
		anvilEntry("3337"),
	}))
}

func TestValidateConfig_ChecksEveryEntry(t *testing.T) {
	// Sim chain followed by a real chain: with the default Anvil key, the
	// second entry should trigger the "real chain" failure even though the
	// first is fine.
	t.Setenv(privateKeyEnvVar, "")
	c := &component{}
	err := c.ValidateConfig([]map[string]any{
		anvilEntry("1337"),
		anvilEntry("1"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "real chain")
}
