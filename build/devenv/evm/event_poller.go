package evm

import (
	"context"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type eventKey struct {
	chainSelector uint64
	msgNum        uint64
	messageID     protocol.Bytes32
}

type pollerResult[T any] struct {
	event T
	err   error
}

// eventPoller polls for on-chain events and delivers them to registered waiters.
// Waiters may register by sequence number or by message ID; two separate maps
// provide O(1) lookup for each key type.
type eventPoller[T any] struct {
	ethClient          *ethclient.Client
	logger             zerolog.Logger
	eventName          string
	lastScannedBlock   uint64
	waitersBySeqNum    map[eventKey]chan pollerResult[T]
	waitersByMessageID map[eventKey]chan pollerResult[T]
	cachedBySeqNum     map[eventKey]pollerResult[T]
	cachedByMessageID  map[eventKey]pollerResult[T]
	mu                 sync.Mutex
	running            bool
	stopCh             chan struct{}
	pollFn             func(start, end uint64) (map[eventKey]T, error)
}

func newEventPoller[T any](
	ethClient *ethclient.Client,
	logger zerolog.Logger,
	eventName string,
	pollFn func(start, end uint64) (map[eventKey]T, error),
) *eventPoller[T] {
	return &eventPoller[T]{
		ethClient:          ethClient,
		logger:             logger,
		eventName:          eventName,
		waitersBySeqNum:    make(map[eventKey]chan pollerResult[T]),
		waitersByMessageID: make(map[eventKey]chan pollerResult[T]),
		cachedBySeqNum:     make(map[eventKey]pollerResult[T]),
		cachedByMessageID:  make(map[eventKey]pollerResult[T]),
		pollFn:             pollFn,
	}
}

func (p *eventPoller[T]) registerByMessageID(ctx context.Context, key eventKey) <-chan pollerResult[T] {
	p.mu.Lock()
	defer p.mu.Unlock()

	msgIDKey := eventKey{chainSelector: key.chainSelector, messageID: key.messageID}

	if cachedResult, found := p.cachedByMessageID[msgIDKey]; found {
		resultCh := make(chan pollerResult[T], 1)
		p.logger.Debug().
			Uint64("chainSelector", key.chainSelector).
			Bytes("messageID", key.messageID[:]).
			Str("event", p.eventName).
			Msg("Cache hit")
		resultCh <- cachedResult
		close(resultCh)
		return resultCh
	}

	if existingCh, exists := p.waitersByMessageID[msgIDKey]; exists {
		return existingCh
	}

	resultCh := make(chan pollerResult[T], 1)
	p.waitersByMessageID[msgIDKey] = resultCh
	go func() {
		<-ctx.Done()
		p.mu.Lock()
		defer p.mu.Unlock()
		if ch, exists := p.waitersByMessageID[msgIDKey]; exists {
			delete(p.waitersByMessageID, msgIDKey)
			ch <- pollerResult[T]{err: ctx.Err()}
			close(ch)
		}
	}()
	if !p.running {
		p.running = true
		p.stopCh = make(chan struct{})
		go p.run()
	}
	return resultCh
}

func (p *eventPoller[T]) registerBySequenceNumber(ctx context.Context, key eventKey) <-chan pollerResult[T] {
	p.mu.Lock()
	defer p.mu.Unlock()

	seqKey := eventKey{chainSelector: key.chainSelector, msgNum: key.msgNum}

	if cachedResult, found := p.cachedBySeqNum[seqKey]; found {
		resultCh := make(chan pollerResult[T], 1)
		p.logger.Debug().
			Uint64("chainSelector", key.chainSelector).
			Uint64("seq", key.msgNum).
			Str("event", p.eventName).
			Msg("Cache hit")
		resultCh <- cachedResult
		close(resultCh)
		return resultCh
	}

	if existingCh, exists := p.waitersBySeqNum[seqKey]; exists {
		return existingCh
	}

	resultCh := make(chan pollerResult[T], 1)
	p.waitersBySeqNum[seqKey] = resultCh
	go func() {
		<-ctx.Done()
		p.mu.Lock()
		defer p.mu.Unlock()
		if ch, exists := p.waitersBySeqNum[seqKey]; exists {
			delete(p.waitersBySeqNum, seqKey)
			ch <- pollerResult[T]{err: ctx.Err()}
			close(ch)
		}
	}()
	if !p.running {
		p.running = true
		p.stopCh = make(chan struct{})
		go p.run()
	}
	return resultCh
}

func (p *eventPoller[T]) run() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.poll()
		}
	}
}

func (p *eventPoller[T]) poll() {
	p.mu.Lock()
	if len(p.waitersBySeqNum) == 0 && len(p.waitersByMessageID) == 0 {
		p.running = false
		close(p.stopCh)
		p.mu.Unlock()
		return
	}
	lastScanned := p.lastScannedBlock
	p.mu.Unlock()

	latestBlock, err := p.ethClient.BlockNumber(context.Background())
	if err != nil {
		p.logger.Warn().Err(err).Str("event", p.eventName).Msg("Failed to get latest block number")
		return
	}

	if latestBlock <= lastScanned {
		return
	}

	events, err := p.pollFn(lastScanned+1, latestBlock)
	if err != nil {
		p.logger.Warn().Err(err).Str("event", p.eventName).Msg("Failed to poll events")
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for key, event := range events {
		result := pollerResult[T]{event: event}
		p.addToCache(key, result)

		seqKey := eventKey{chainSelector: key.chainSelector, msgNum: key.msgNum}
		if ch, exists := p.waitersBySeqNum[seqKey]; exists {
			delete(p.waitersBySeqNum, seqKey)
			p.logger.Info().
				Uint64("chainSelector", key.chainSelector).
				Uint64("seqNo", key.msgNum).
				Str("event", p.eventName).
				Msg("Event received")
			ch <- result
			close(ch)
		}

		if key.messageID != (protocol.Bytes32{}) {
			msgIDKey := eventKey{chainSelector: key.chainSelector, messageID: key.messageID}
			if ch, exists := p.waitersByMessageID[msgIDKey]; exists {
				delete(p.waitersByMessageID, msgIDKey)
				p.logger.Info().
					Uint64("chainSelector", key.chainSelector).
					Bytes("messageID", key.messageID[:]).
					Str("event", p.eventName).
					Msg("Event received")
				ch <- result
				close(ch)
			}
		}
	}

	p.lastScannedBlock = latestBlock
}

func (p *eventPoller[T]) addToCache(key eventKey, result pollerResult[T]) {
	seqKey := eventKey{chainSelector: key.chainSelector, msgNum: key.msgNum}
	if _, exists := p.cachedBySeqNum[seqKey]; !exists {
		p.cachedBySeqNum[seqKey] = result
	}

	if key.messageID != (protocol.Bytes32{}) {
		msgIDKey := eventKey{chainSelector: key.chainSelector, messageID: key.messageID}
		if _, exists := p.cachedByMessageID[msgIDKey]; !exists {
			p.cachedByMessageID[msgIDKey] = result
		}
	}
}
