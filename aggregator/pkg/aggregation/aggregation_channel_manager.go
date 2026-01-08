package aggregation

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

var OrphanRecoveryClientID = "orphan_recovery"

type ChannelManager struct {
	clientChannel      map[string]chan aggregationRequest
	clientOrder        []string
	aggregationChannel chan aggregationRequest
	wakeUp             chan struct{}
}

func NewChannelManager(clientIDs []string, bufferSize int) *ChannelManager {
	manager := &ChannelManager{
		clientChannel:      make(map[string]chan aggregationRequest),
		clientOrder:        make([]string, 0, len(clientIDs)),
		aggregationChannel: make(chan aggregationRequest, len(clientIDs)),
		wakeUp:             make(chan struct{}, 1),
	}
	for _, clientID := range clientIDs {
		manager.clientChannel[clientID] = make(chan aggregationRequest, bufferSize)
		manager.clientOrder = append(manager.clientOrder, clientID)
	}
	return manager
}

func NewChannelManagerFromConfig(config *model.AggregatorConfig) *ChannelManager {
	clientIDs := make([]string, 0)
	for _, client := range config.APIClients {
		clientIDs = append(clientIDs, client.ClientID)
	}
	clientIDs = append(clientIDs, OrphanRecoveryClientID)
	return NewChannelManager(clientIDs, config.Aggregation.ChannelBufferSize)
}

func (m *ChannelManager) Enqueue(clientID string, req aggregationRequest, maxBlockTime time.Duration) error {
	ch, ok := m.clientChannel[clientID]
	if !ok {
		return fmt.Errorf("client channel not found: %s", clientID)
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

func (m *ChannelManager) getAggregationChannel() chan aggregationRequest {
	return m.aggregationChannel
}

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
				case m.aggregationChannel <- req:
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
