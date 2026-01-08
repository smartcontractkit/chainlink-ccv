package aggregation

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

func TestNewChannelManager_CreatesChannelsForAllClients(t *testing.T) {
	tests := []struct {
		name       string
		keys       []model.ChannelKey
		bufferSize int
	}{
		{
			name:       "single client",
			keys:       []model.ChannelKey{"client1"},
			bufferSize: 10,
		},
		{
			name:       "multiple clients",
			keys:       []model.ChannelKey{"client1", "client2", "client3"},
			bufferSize: 5,
		},
		{
			name:       "empty client list",
			keys:       []model.ChannelKey{},
			bufferSize: 10,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manager := NewChannelManager(tc.keys, tc.bufferSize)

			require.NotNil(t, manager)
			require.NotNil(t, manager.AggregationChannel)
			assert.Len(t, manager.clientChannel, len(tc.keys))
			assert.Len(t, manager.clientOrder, len(tc.keys))
			require.NotNil(t, manager.wakeUp)

			for _, key := range tc.keys {
				ch, ok := manager.clientChannel[key]
				assert.True(t, ok)
				assert.NotNil(t, ch)
				assert.Equal(t, tc.bufferSize, cap(ch))
			}

			assert.Equal(t, len(tc.keys), cap(manager.AggregationChannel))
		})
	}
}

func TestNewChannelManagerFromConfig_ExtractsClientIDsAndAddsOrphanRecovery(t *testing.T) {
	tests := []struct {
		name         string
		config       *model.AggregatorConfig
		expectedKeys []model.ChannelKey
	}{
		{
			name: "config with multiple clients",
			config: &model.AggregatorConfig{
				APIClients: []*model.ClientConfig{
					{ClientID: "client1"},
					{ClientID: "client2"},
				},
				Aggregation: model.AggregationConfig{
					ChannelBufferSize: 10,
				},
			},
			expectedKeys: []model.ChannelKey{"client1", "client2", model.OrphanRecoveryChannelKey},
		},
		{
			name: "config with no clients adds only orphan_recovery",
			config: &model.AggregatorConfig{
				APIClients: []*model.ClientConfig{},
				Aggregation: model.AggregationConfig{
					ChannelBufferSize: 5,
				},
			},
			expectedKeys: []model.ChannelKey{model.OrphanRecoveryChannelKey},
		},
		{
			name: "config with single client",
			config: &model.AggregatorConfig{
				APIClients: []*model.ClientConfig{
					{ClientID: "verifier-1"},
				},
				Aggregation: model.AggregationConfig{
					ChannelBufferSize: 20,
				},
			},
			expectedKeys: []model.ChannelKey{"verifier-1", model.OrphanRecoveryChannelKey},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manager := NewChannelManagerFromConfig(tc.config)

			require.NotNil(t, manager)
			assert.Len(t, manager.clientChannel, len(tc.expectedKeys))

			for _, key := range tc.expectedKeys {
				ch, ok := manager.clientChannel[key]
				assert.True(t, ok, "expected channel for key %s", key)
				assert.NotNil(t, ch)
				assert.Equal(t, tc.config.Aggregation.ChannelBufferSize, cap(ch))
			}
		})
	}
}

func TestEnqueue_SucceedsForExistingKey(t *testing.T) {
	manager := NewChannelManager([]model.ChannelKey{"client1", "client2"}, 10)

	err := manager.Enqueue("client1", aggregationRequest{ChannelKey: "client1"}, time.Millisecond)

	assert.NoError(t, err)
}

func TestEnqueue_ReturnsErrorForNonExistingKey(t *testing.T) {
	manager := NewChannelManager([]model.ChannelKey{"client1"}, 10)

	err := manager.Enqueue("non_existing_key", aggregationRequest{ChannelKey: "non_existing_key"}, time.Millisecond)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "channel not found")
}

func TestEnqueue_ReturnsErrorWhenChannelFull(t *testing.T) {
	manager := NewChannelManager([]model.ChannelKey{"client1"}, 1)

	err1 := manager.Enqueue("client1", aggregationRequest{ChannelKey: "client1"}, time.Millisecond)
	assert.NoError(t, err1)

	err2 := manager.Enqueue("client1", aggregationRequest{ChannelKey: "client1"}, time.Millisecond)
	assert.Error(t, err2)
}

func TestGetAggregationChannel_ReturnsNonNilChannel(t *testing.T) {
	manager := NewChannelManager([]model.ChannelKey{"client1"}, 10)

	assert.NotNil(t, manager.AggregationChannel)
}

func TestStart_ForwardsRequestsFromClientChannelToAggregationChannel(t *testing.T) {
	manager := NewChannelManager([]model.ChannelKey{"client1", "client2"}, 10)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startDone := make(chan struct{})
	go func() {
		_ = manager.Start(ctx)
		close(startDone)
	}()

	time.Sleep(10 * time.Millisecond)

	expectedRequest := aggregationRequest{
		AggregationKey: "test-aggregation-key",
		MessageID:      model.MessageID{4, 5, 6},
		ChannelKey:     "client1",
	}

	err := manager.Enqueue("client1", expectedRequest, time.Millisecond)
	require.NoError(t, err)

	select {
	case receivedRequest := <-manager.AggregationChannel:
		assert.Equal(t, expectedRequest, receivedRequest)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for request on aggregation channel")
	}

	cancel()

	select {
	case <-startDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for Start to complete")
	}
}

func TestStart_StopsOnContextCancellation(t *testing.T) {
	manager := NewChannelManager([]model.ChannelKey{"client1"}, 10)

	ctx, cancel := context.WithCancel(context.Background())

	startDone := make(chan struct{})
	go func() {
		_ = manager.Start(ctx)
		close(startDone)
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case <-startDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Start did not complete after context cancellation")
	}
}

func TestStart_ReceivesMultipleRequestsFromMultipleClients(t *testing.T) {
	manager := NewChannelManager([]model.ChannelKey{"client1", "client2"}, 20)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = manager.Start(ctx) }()

	time.Sleep(10 * time.Millisecond)

	client1RequestCount := 3
	client2RequestCount := 10
	totalExpected := client1RequestCount + client2RequestCount

	for i := 0; i < client1RequestCount; i++ {
		err := manager.Enqueue("client1", aggregationRequest{
			AggregationKey: "key-client1",
			MessageID:      model.MessageID{byte(i)},
			ChannelKey:     "client1",
		}, time.Millisecond)
		require.NoError(t, err)
	}

	for i := 0; i < client2RequestCount; i++ {
		err := manager.Enqueue("client2", aggregationRequest{
			AggregationKey: "key-client2",
			MessageID:      model.MessageID{byte(i + 100)},
			ChannelKey:     "client2",
		}, time.Millisecond)
		require.NoError(t, err)
	}

	received := make([]aggregationRequest, 0, totalExpected)
	timeout := time.After(500 * time.Millisecond)

	for len(received) < totalExpected {
		select {
		case req := <-manager.AggregationChannel:
			received = append(received, req)
		case <-timeout:
			t.Fatalf("timeout: received only %d of %d expected requests", len(received), totalExpected)
		}
	}

	assert.Len(t, received, totalExpected)

	client1Received := 0
	client2Received := 0
	for _, req := range received {
		switch req.ChannelKey {
		case "client1":
			client1Received++
		case "client2":
			client2Received++
		}
	}

	assert.Equal(t, client1RequestCount, client1Received, "expected %d requests from client1", client1RequestCount)
	assert.Equal(t, client2RequestCount, client2Received, "expected %d requests from client2", client2RequestCount)
}

// The aggregationChannel size is 2 so the maximum a busy client can enqueue is 2.
// The quiet client will then be picked up by the round robin scheduling at 3.
func TestStart_FairSchedulingPreventsBusyClientStarvation(t *testing.T) {
	manager := NewChannelManager([]model.ChannelKey{"busy", "quiet"}, 100)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = manager.Start(ctx) }()
	time.Sleep(10 * time.Millisecond)

	for i := 0; i < 50; i++ {
		err := manager.Enqueue("busy", aggregationRequest{
			ChannelKey: "busy",
			MessageID:  model.MessageID{byte(i)},
		}, time.Millisecond)
		require.NoError(t, err)
	}

	err := manager.Enqueue("quiet", aggregationRequest{
		ChannelKey: "quiet",
		MessageID:  model.MessageID{0xFF},
	}, time.Millisecond)
	require.NoError(t, err)

	received := make([]aggregationRequest, 0)
	timeout := time.After(500 * time.Millisecond)

	for len(received) <= 3 {
		select {
		case req := <-manager.AggregationChannel:
			received = append(received, req)
		case <-timeout:
			t.Fatalf("timeout: received only %d of %d expected requests", len(received), 10)
		}
	}

	assert.Contains(t, received, aggregationRequest{
		ChannelKey: "quiet",
		MessageID:  model.MessageID{0xFF},
	}, "quiet client request should be received")
}
