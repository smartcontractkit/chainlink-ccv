package aggregation

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

type ChannelManager struct {
	clientChannel      map[model.ChannelKey]chan aggregationRequest
	clientOrder        []model.ChannelKey
	AggregationChannel chan aggregationRequest
	wakeUp             chan struct{}
	closed             atomic.Bool

	// We deduplicate requests based on their unique ID (AggregationKey + MessageID) to avoid processing the same request multiple times.
	// When the service is under heavy load the requests will come from multiple clients at once and we can reduce pressure by only processing one of them per messages.
	// If 2 requests for the same message reach the channel manager at the same time it is fine to drop them since we already persisted both verification but did not aggregate yet.
	currentlyQueued     map[string]struct{}
	currentlyQueuedLock sync.Mutex
}

func NewChannelManager(keys []model.ChannelKey, bufferSize int) *ChannelManager {
	manager := &ChannelManager{
		clientChannel:       make(map[model.ChannelKey]chan aggregationRequest),
		clientOrder:         make([]model.ChannelKey, 0, len(keys)),
		AggregationChannel:  make(chan aggregationRequest, len(keys)),
		wakeUp:              make(chan struct{}, 1),
		currentlyQueued:     make(map[string]struct{}),
		currentlyQueuedLock: sync.Mutex{},
	}
	for _, key := range keys {
		manager.clientChannel[key] = make(chan aggregationRequest, bufferSize)
		manager.clientOrder = append(manager.clientOrder, key)
	}
	return manager
}

func NewChannelManagerFromConfig(config *model.AggregatorConfig) *ChannelManager {
	keys := make([]model.ChannelKey, 0, len(config.APIClients)+1)
	for _, client := range config.APIClients {
		keys = append(keys, model.ChannelKey(client.ClientID))
	}
	keys = append(keys, model.OrphanRecoveryChannelKey)
	return NewChannelManager(keys, config.Aggregation.ChannelBufferSize)
}

func (m *ChannelManager) Enqueue(ctx context.Context, key model.ChannelKey, req aggregationRequest, maxBlockTime time.Duration) error {
	if m.closed.Load() {
		return common.ErrShuttingDown
	}

	ch, ok := m.clientChannel[key]
	if !ok {
		return fmt.Errorf("channel not found for key: %s", key)
	}

	queued, err := m.enqueueIfNotQueued(ctx, ch, req)
	if err != nil {
		return err
	}
	if !queued {
		return nil
	}
	select {
	case m.wakeUp <- struct{}{}:
	default:
	}
	return nil
}

func (m *ChannelManager) enqueueIfNotQueued(
	ctx context.Context,
	ch chan<- aggregationRequest,
	req aggregationRequest,
) (bool, error) {
	// Reserve the deduplication key and enqueue while holding the same lock.
	// Otherwise Start can dequeue and delete the key between the send and a
	// later marker write, leaving a stale key that suppresses every
	// subsequent quorum check for this message.
	m.currentlyQueuedLock.Lock()
	defer m.currentlyQueuedLock.Unlock()

	requestID := req.ID()
	if _, exists := m.currentlyQueued[requestID]; exists {
		return false, nil
	}
	select {
	case ch <- req:
		m.currentlyQueued[requestID] = struct{}{}
		return true, nil
	case <-ctx.Done():
		return false, ctx.Err()
	default:
		return false, common.ErrAggregationChannelFull
	}
}

func (m *ChannelManager) markAsDequeued(req aggregationRequest) {
	m.currentlyQueuedLock.Lock()
	defer m.currentlyQueuedLock.Unlock()
	delete(m.currentlyQueued, req.ID())
}

// Start runs the fair scheduling loop in a single goroutine.
// Using a single goroutine ensures deterministic round-robin ordering across client channels,
// preventing any client from starving others regardless of request volume.
// The wakeUp channel avoids busy-waiting when all client channels are empty -
// Enqueue signals it after adding work, allowing Start to sleep until there's something to process.
//
// On context cancellation, Start sets the closed flag to reject new Enqueue calls,
// then fair-drains all remaining items from client channels into AggregationChannel
// before returning.
func (m *ChannelManager) Start(ctx context.Context) error {
	if len(m.clientOrder) == 0 {
		<-ctx.Done()
		m.closed.Store(true)
		close(m.AggregationChannel)
		return nil
	}

	currentIdx := 0
	for {
		foundWork := false
		for i := 0; i < len(m.clientOrder); i++ {
			idx := (currentIdx + i) % len(m.clientOrder)
			ch := m.clientChannel[m.clientOrder[idx]]

			if len(ch) > 0 {
				req := <-ch
				select {
				case m.AggregationChannel <- req:
					m.markAsDequeued(req)
				case <-ctx.Done():
					m.closed.Store(true)
					m.AggregationChannel <- req
					m.drainClientChannels()
					close(m.AggregationChannel)
					return nil
				}
				foundWork = true
				currentIdx = (idx + 1) % len(m.clientOrder)
				break
			}
		}

		if !foundWork {
			select {
			case <-ctx.Done():
				m.closed.Store(true)
				m.drainClientChannels()
				close(m.AggregationChannel)
				return nil
			case <-m.wakeUp:
			}
		}
	}
}

func (m *ChannelManager) drainClientChannels() {
	for {
		foundWork := false
		for _, key := range m.clientOrder {
			ch := m.clientChannel[key]
			if len(ch) > 0 {
				m.AggregationChannel <- <-ch
				foundWork = true
			}
		}
		if !foundWork {
			return
		}
	}
}
