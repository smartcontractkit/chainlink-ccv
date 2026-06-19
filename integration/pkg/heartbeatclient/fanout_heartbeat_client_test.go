package heartbeatclient

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type stubSender struct {
	resp HeartbeatResponse
	err  error
}

func (s *stubSender) SendHeartbeat(_ context.Context, _ map[uint64]uint64) (HeartbeatResponse, error) {
	return s.resp, s.err
}
func (s *stubSender) Close() error { return nil }

func newFanOutSender(t *testing.T, senders ...labeledSender) *FanOutHeartbeatSender {
	t.Helper()
	return &FanOutHeartbeatSender{senders: senders, lggr: logger.Test(t)}
}

func TestFanOutHeartbeat_PartialFailureIsNotAnError(t *testing.T) {
	f := newFanOutSender(t,
		labeledSender{label: "a", sender: &stubSender{resp: HeartbeatResponse{AggregatorID: "a", Timestamp: 7}}},
		labeledSender{label: "b", sender: &stubSender{err: errors.New("down")}},
	)

	resp, err := f.SendHeartbeat(context.Background(), map[uint64]uint64{1: 100})
	require.NoError(t, err, "a single aggregator failure must not fail the heartbeat")
	assert.Equal(t, "a", resp.AggregatorID, "returns the first successful response")
}

func TestFanOutHeartbeat_AllFailIsAnError(t *testing.T) {
	f := newFanOutSender(t,
		labeledSender{label: "a", sender: &stubSender{err: errors.New("down-a")}},
		labeledSender{label: "b", sender: &stubSender{err: errors.New("down-b")}},
	)

	_, err := f.SendHeartbeat(context.Background(), map[uint64]uint64{1: 100})
	require.Error(t, err)
	assert.ErrorContains(t, err, "all aggregators failed")
	assert.ErrorContains(t, err, "down-a")
	assert.ErrorContains(t, err, "down-b")
}
