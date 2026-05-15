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

func TestFilterCLModeNOPs_SkipsStandalone(t *testing.T) {
	got := filterCLModeNOPs(
		[]shared.NOPAlias{"nop1", "nop2", "nop3"},
		[]NOPInput{
			{Alias: "nop1", Mode: shared.NOPModeCL},
			{Alias: "nop2", Mode: shared.NOPModeStandalone},
			{Alias: "nop3", Mode: shared.NOPModeCL},
		},
	)
	assert.Equal(t, []shared.NOPAlias{"nop1", "nop3"}, got)
}

func TestFilterCLModeNOPs_TreatsMissingAsNotCL(t *testing.T) {
	// nopGhost is not in the NOP slice → mode lookup returns "" → not CL → excluded.
	got := filterCLModeNOPs(
		[]shared.NOPAlias{"nop1", "nopGhost"},
		[]NOPInput{{Alias: "nop1", Mode: shared.NOPModeCL}},
	)
	assert.Equal(t, []shared.NOPAlias{"nop1"}, got)
}

func TestAllNOPAliases_PreservesInputOrder(t *testing.T) {
	got := allNOPAliases([]NOPInput{{Alias: "z"}, {Alias: "a"}, {Alias: "m"}})
	assert.Equal(t, []shared.NOPAlias{"z", "a", "m"}, got)
}
