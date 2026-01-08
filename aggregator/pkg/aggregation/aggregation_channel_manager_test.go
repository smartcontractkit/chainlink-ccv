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
		clientIDs  []string
		bufferSize int
	}{
		{
			name:       "single client",
			clientIDs:  []string{"client1"},
			bufferSize: 10,
		},
		{
			name:       "multiple clients",
			clientIDs:  []string{"client1", "client2", "client3"},
			bufferSize: 5,
		},
		{
			name:       "empty client list",
			clientIDs:  []string{},
			bufferSize: 10,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manager := NewChannelManager(tc.clientIDs, tc.bufferSize)

			require.NotNil(t, manager)
			require.NotNil(t, manager.aggregationChannel)
			assert.Len(t, manager.clientChannel, len(tc.clientIDs))
			assert.Len(t, manager.clientOrder, len(tc.clientIDs))
			require.NotNil(t, manager.wakeUp)

			for _, clientID := range tc.clientIDs {
				ch, ok := manager.clientChannel[clientID]
				assert.True(t, ok)
				assert.NotNil(t, ch)
				assert.Equal(t, tc.bufferSize, cap(ch))
			}

			assert.Equal(t, len(tc.clientIDs), cap(manager.aggregationChannel))
		})
	}
}

func TestNewChannelManagerFromConfig_ExtractsClientIDsAndAddsOrphanRecovery(t *testing.T) {
	tests := []struct {
		name              string
		config            *model.AggregatorConfig
		expectedClientIDs []string
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
			expectedClientIDs: []string{"client1", "client2", OrphanRecoveryClientID},
		},
		{
			name: "config with no clients adds only orphan_recovery",
			config: &model.AggregatorConfig{
				APIClients: []*model.ClientConfig{},
				Aggregation: model.AggregationConfig{
					ChannelBufferSize: 5,
				},
			},
			expectedClientIDs: []string{OrphanRecoveryClientID},
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
			expectedClientIDs: []string{"verifier-1", OrphanRecoveryClientID},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manager := NewChannelManagerFromConfig(tc.config)

			require.NotNil(t, manager)
			assert.Len(t, manager.clientChannel, len(tc.expectedClientIDs))

			for _, clientID := range tc.expectedClientIDs {
				ch, ok := manager.clientChannel[clientID]
				assert.True(t, ok, "expected channel for client %s", clientID)
				assert.NotNil(t, ch)
				assert.Equal(t, tc.config.Aggregation.ChannelBufferSize, cap(ch))
			}
		})
	}
}

func TestEnqueue_SucceedsForExistingClient(t *testing.T) {
	manager := NewChannelManager([]string{"client1", "client2"}, 10)

	err := manager.Enqueue("client1", aggregationRequest{ClientID: "client1"}, time.Millisecond)

	assert.NoError(t, err)
}

func TestEnqueue_ReturnsErrorForNonExistingClient(t *testing.T) {
	manager := NewChannelManager([]string{"client1"}, 10)

	err := manager.Enqueue("non_existing_client", aggregationRequest{ClientID: "non_existing_client"}, time.Millisecond)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client channel not found")
}

func TestEnqueue_ReturnsErrorWhenChannelFull(t *testing.T) {
	manager := NewChannelManager([]string{"client1"}, 1)

	err1 := manager.Enqueue("client1", aggregationRequest{ClientID: "client1"}, time.Millisecond)
	assert.NoError(t, err1)

	err2 := manager.Enqueue("client1", aggregationRequest{ClientID: "client1"}, time.Millisecond)
	assert.Error(t, err2)
}

func TestGetAggregationChannel_ReturnsNonNilChannel(t *testing.T) {
	manager := NewChannelManager([]string{"client1"}, 10)

	channel := manager.getAggregationChannel()

	assert.NotNil(t, channel)
}

func TestStart_ForwardsRequestsFromClientChannelToAggregationChannel(t *testing.T) {
	manager := NewChannelManager([]string{"client1", "client2"}, 10)

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
		ClientID:       "client1",
	}

	err := manager.Enqueue("client1", expectedRequest, time.Millisecond)
	require.NoError(t, err)

	select {
	case receivedRequest := <-manager.getAggregationChannel():
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
	manager := NewChannelManager([]string{"client1"}, 10)

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
	manager := NewChannelManager([]string{"client1", "client2"}, 20)

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
			ClientID:       "client1",
		}, time.Millisecond)
		require.NoError(t, err)
	}

	for i := 0; i < client2RequestCount; i++ {
		err := manager.Enqueue("client2", aggregationRequest{
			AggregationKey: "key-client2",
			MessageID:      model.MessageID{byte(i + 100)},
			ClientID:       "client2",
		}, time.Millisecond)
		require.NoError(t, err)
	}

	received := make([]aggregationRequest, 0, totalExpected)
	timeout := time.After(500 * time.Millisecond)

	for len(received) < totalExpected {
		select {
		case req := <-manager.getAggregationChannel():
			received = append(received, req)
		case <-timeout:
			t.Fatalf("timeout: received only %d of %d expected requests", len(received), totalExpected)
		}
	}

	assert.Len(t, received, totalExpected)

	client1Received := 0
	client2Received := 0
	for _, req := range received {
		switch req.ClientID {
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
	manager := NewChannelManager([]string{"busy", "quiet"}, 100)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = manager.Start(ctx) }()
	time.Sleep(10 * time.Millisecond)

	for i := 0; i < 50; i++ {
		err := manager.Enqueue("busy", aggregationRequest{
			ClientID:  "busy",
			MessageID: model.MessageID{byte(i)},
		}, time.Millisecond)
		require.NoError(t, err)
	}

	err := manager.Enqueue("quiet", aggregationRequest{
		ClientID:  "quiet",
		MessageID: model.MessageID{0xFF},
	}, time.Millisecond)
	require.NoError(t, err)

	received := make([]aggregationRequest, 0)
	timeout := time.After(500 * time.Millisecond)

	for len(received) <= 3 {
		select {
		case req := <-manager.getAggregationChannel():
			received = append(received, req)
		case <-timeout:
			t.Fatalf("timeout: received only %d of %d expected requests", len(received), 10)
		}
	}

	assert.Contains(t, received, aggregationRequest{
		ClientID:  "quiet",
		MessageID: model.MessageID{0xFF},
	}, "quiet client request should be received")
}
