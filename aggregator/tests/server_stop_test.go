package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/testutil"
)

func TestServerStop_ReturnsWithoutSignal(t *testing.T) {
	source, dest := testutil.GenerateVerifierAddresses(t)
	committee := testutil.NewCommitteeFixture(source, dest, testutil.NewSignerFixture(t, "node1").Signer)
	_, server, _, cleanup, err := createServer(t, WithCommitteeConfig(committee))
	require.NoError(t, err)
	t.Cleanup(cleanup)

	stopped := make(chan error, 1)
	go func() { stopped <- server.Stop() }()
	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("Stop did not return after the run group drained")
	}
}
