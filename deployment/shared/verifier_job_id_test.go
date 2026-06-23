package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifierJobID_PerAggregator(t *testing.T) {
	scope := VerifierJobScope{CommitteeQualifier: "default"}
	id := NewVerifierJobID("nop1", "agg-a", scope)

	assert.Equal(t, "agg-a-default-verifier", id.GetVerifierID())
	assert.Equal(t, JobID("nop1-agg-a-default-verifier"), id.ToJobID())
	assert.True(t, scope.IsJobInScope(id.ToJobID()))
}

func TestVerifierJobID_Consolidated(t *testing.T) {
	scope := VerifierJobScope{CommitteeQualifier: "default"}
	id := NewConsolidatedVerifierJobID("nop1", scope)

	assert.Equal(t, "default-verifier", id.GetVerifierID(), "consolidated verifier id omits the aggregator name")
	assert.Equal(t, JobID("nop1-default-verifier"), id.ToJobID())
	// Scope matching must still recognize consolidated jobs so orphaned-job cleanup works across
	// the topology switch.
	assert.True(t, scope.IsJobInScope(id.ToJobID()))
}
