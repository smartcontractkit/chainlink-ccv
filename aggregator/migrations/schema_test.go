package migrations

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common/jobqueue"
)

// TestAggregationJobsMatchesJobqueueSchema keeps the migration a verbatim copy of the jobqueue DDL.
func TestAggregationJobsMatchesJobqueueSchema(t *testing.T) {
	migration, err := PostgresMigrations.ReadFile("postgres/00006_create_aggregation_jobs.sql")
	require.NoError(t, err)
	assert.Contains(t, string(migration), jobqueue.CreateTablesSQLSerializePerKey("ccv_aggregation_jobs"))
}
