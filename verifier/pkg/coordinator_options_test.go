package verifier

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/smartcontractkit/chainlink-ccv/common/jobqueue"
)

func TestCoordinatorQueueKeys(t *testing.T) {
	// The Chainlink-node constructor passes no options and its schema has no dedup_key.
	assert.Equal(t, jobqueue.MessageKeyColumns, newCoordinatorOptions().queueKeys)
	assert.Equal(t, jobqueue.MessageKeyColumns, newCoordinatorOptions(WithSourceRecovery()).queueKeys)
	assert.Equal(t, jobqueue.DedupKeyColumn, newCoordinatorOptions(WithDedupKeyColumn()).queueKeys)
}
