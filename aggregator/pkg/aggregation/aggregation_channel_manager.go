package aggregation

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

type ChannelManager struct {
	clientChannel      map[model.ChannelKey]chan aggregationRequest
	clientOrder        []model.ChannelKey
	AggregationChannel chan aggregationRequest
	wakeUp             chan struct{}
}

func NewChannelManager(keys []model.ChannelKey, bufferSize int) *ChannelManager {
	manager := &ChannelManager{
		clientChannel:      make(map[model.ChannelKey]chan aggregationRequest),
		clientOrder:        make([]model.ChannelKey, 0, len(keys)),
		AggregationChannel: make(chan aggregationRequest, len(keys)),
		wakeUp:             make(chan struct{}, 1),
	}
	for _, key := range keys {
		manager.clientChannel[key] = make(chan aggregationRequest, bufferSize)
		manager.clientOrder = append(manager.clientOrder, key)
	}
	return manager
}

func NewChannelManagerFromConfig(config *model.AggregatorConfig) *ChannelManager {
	keys := make([]model.ChannelKey, 0)
	for _, client := range config.APIClients {
		keys = append(keys, model.ChannelKey(client.ClientID))
	}
	keys = append(keys, model.OrphanRecoveryChannelKey)
	return NewChannelManager(keys, config.Aggregation.ChannelBufferSize)
}

func (m *ChannelManager) Enqueue(key model.ChannelKey, req aggregationRequest, maxBlockTime time.Duration) error {
	ch, ok := m.clientChannel[key]
	if !ok {
		return fmt.Errorf("channel not found for key: %s", key)
	}
	select {
	case ch <- req:
		select {
		case m.wakeUp <- struct{}{}:
		default:
		}
		return nil
	case <-time.After(maxBlockTime):
		return common.ErrAggregationChannelFull
	}
}

// Start runs the fair scheduling loop in a single goroutine.
// Using a single goroutine ensures deterministic round-robin ordering across client channels,
// preventing any client from starving others regardless of request volume.
// The wakeUp channel avoids busy-waiting when all client channels are empty -
// Enqueue signals it after adding work, allowing Start to sleep until there's something to process.
func (m *ChannelManager) Start(ctx context.Context) error {
	if len(m.clientOrder) == 0 {
		<-ctx.Done()
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
				case <-ctx.Done():
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
				return nil
			case <-m.wakeUp:
			}
		}
	}
}
