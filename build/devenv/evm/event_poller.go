package evm

import (
	"context"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog"
)

type eventKey struct {
	chainSelector uint64
	seqNo         uint64
}

type pollerResult[T any] struct {
	event T
	err   error
}

type eventPoller[T any] struct {
	ethClient        *ethclient.Client
	logger           zerolog.Logger
	eventName        string
	lastScannedBlock uint64
	waiters          map[eventKey]chan pollerResult[T]
	cachedEvents     map[eventKey]pollerResult[T]
	mu               sync.Mutex
	running          bool
	stopCh           chan struct{}
	pollFn           func(start, end uint64) (map[eventKey]T, error)
}

func newEventPoller[T any](
	ethClient *ethclient.Client,
	logger zerolog.Logger,
	eventName string,
	pollFn func(start, end uint64) (map[eventKey]T, error),
) *eventPoller[T] {
	return &eventPoller[T]{
		ethClient:    ethClient,
		logger:       logger,
		eventName:    eventName,
		waiters:      make(map[eventKey]chan pollerResult[T]),
		cachedEvents: make(map[eventKey]pollerResult[T]),
		pollFn:       pollFn,
	}
}

func (p *eventPoller[T]) register(ctx context.Context, chainSelector, seq uint64) <-chan pollerResult[T] {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := eventKey{chainSelector: chainSelector, seqNo: seq}
	resultCh := make(chan pollerResult[T], 1)

	if cachedResult, found := p.cachedEvents[key]; found {
		p.logger.Debug().
			Uint64("chainSelector", chainSelector).
			Uint64("seq", seq).
			Str("event", p.eventName).
			Msg("Cache hit")
		resultCh <- cachedResult
		close(resultCh)
		return resultCh
	}

	if existingCh, exists := p.waiters[key]; exists {
		return existingCh
	}

	p.waiters[key] = resultCh

	if !p.running {
		p.running = true
		p.stopCh = make(chan struct{})
		go p.run()
	}

	go func() {
		<-ctx.Done()
		p.mu.Lock()
		defer p.mu.Unlock()
		if ch, exists := p.waiters[key]; exists {
			delete(p.waiters, key)
			ch <- pollerResult[T]{err: ctx.Err()}
			close(ch)
		}
	}()

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
	if len(p.waiters) == 0 {
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

		if ch, exists := p.waiters[key]; exists {
			delete(p.waiters, key)
			p.logger.Info().
				Uint64("chainSelector", key.chainSelector).
				Uint64("seqNo", key.seqNo).
				Str("event", p.eventName).
				Msg("Event received")
			ch <- result
			close(ch)
		}
	}

	p.lastScannedBlock = latestBlock
}

func (p *eventPoller[T]) addToCache(key eventKey, result pollerResult[T]) {
	if _, exists := p.cachedEvents[key]; exists {
		return
	}

	p.cachedEvents[key] = result
}
