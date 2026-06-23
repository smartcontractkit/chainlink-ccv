package changesets

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

func TestNOPInput_GetMode_DefaultsToCL(t *testing.T) {
	assert.Equal(t, shared.NOPModeCL, NOPInput{Alias: "nop1"}.GetMode())
	assert.Equal(t, shared.NOPModeStandalone, NOPInput{Alias: "nop1", Mode: shared.NOPModeStandalone}.GetMode())
}

func TestBuildNOPModes_FillsDefaults(t *testing.T) {
	got := buildNOPModes([]NOPInput{
		{Alias: "nop1"}, // empty mode → default CL
		{Alias: "nop2", Mode: shared.NOPModeStandalone},
	})
	assert.Equal(t, shared.NOPModeCL, got["nop1"])
	assert.Equal(t, shared.NOPModeStandalone, got["nop2"])
}

func TestAllNOPAliases_PreservesInputOrder(t *testing.T) {
	got := allNOPAliases([]NOPInput{{Alias: "z"}, {Alias: "a"}, {Alias: "m"}})
	assert.Equal(t, []shared.NOPAlias{"z", "a", "m"}, got)
}
