package evm

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
)

type closeTrackingClient struct {
	client.Client
	closeCalls atomic.Int32
}

func (c *closeTrackingClient) Close() {
	c.closeCalls.Add(1)
}

type closeTrackingHeadTracker struct {
	heads.Tracker
	closeCalls atomic.Int32
	closeErr   error
}

func (h *closeTrackingHeadTracker) Close() error {
	h.closeCalls.Add(1)
	return h.closeErr
}

func TestFactoryCloseReleasesConstructorResourcesOnce(t *testing.T) {
	selector := protocol.ChainSelector(5009297550715157269)
	wantErr := errors.New("close tracker")
	chainClient := &closeTrackingClient{}
	tracker := &closeTrackingHeadTracker{closeErr: wantErr}
	factory := &factory{
		chainClients: map[protocol.ChainSelector]client.Client{selector: chainClient},
		headTrackers: map[protocol.ChainSelector]heads.Tracker{selector: tracker},
	}

	require.ErrorIs(t, factory.Close(), wantErr)
	require.ErrorIs(t, factory.Close(), wantErr)
	require.Equal(t, int32(1), chainClient.closeCalls.Load())
	require.Equal(t, int32(1), tracker.closeCalls.Load())
}
