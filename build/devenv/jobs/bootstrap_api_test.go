package jobs

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/deployment/registration"
)

func TestBootstrapInfoServerAPIContract(t *testing.T) {
	t.Parallel()
	require.Equal(t, bootstrap.DefaultCSAKeyName, registration.DefaultCSAKeyName)
	require.Equal(t, bootstrap.GetKeysEndpoint, registration.GetKeysEndpoint)
}
