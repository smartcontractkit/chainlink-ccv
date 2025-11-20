package discovery

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/failsafe-go/failsafe-go/circuitbreaker"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ common.MessageDiscovery = (*AggregatorMessageDiscovery)(nil)

type AggregatorMessageDiscovery struct {
	logger           logger.Logger
	config           config.DiscoveryConfig
	aggregatorReader *readers.ResilientReader
	storageSink      common.IndexerStorage
	monitoring       common.IndexerMonitoring
	messageCh        chan protocol.CCVData
	stopCh           chan struct{}
	doneCh           chan struct{}
	readerLock       *sync.Mutex
}

type Option func(*AggregatorMessageDiscovery)

func WithAggregator(aggregator *readers.ResilientReader) Option {
	return func(a *AggregatorMessageDiscovery) {
		a.aggregatorReader = aggregator
	}
}

func WithMonitoring(monitoring common.IndexerMonitoring) Option {
	return func(a *AggregatorMessageDiscovery) {
		a.monitoring = monitoring
	}
}

func WithStorage(storage common.IndexerStorage) Option {
	return func(a *AggregatorMessageDiscovery) {
		a.storageSink = storage
	}
}

func WithLogger(lggr logger.Logger) Option {
	return func(a *AggregatorMessageDiscovery) {
		a.logger = lggr
	}
}

func WithConfig(config config.DiscoveryConfig) Option {
	return func(a *AggregatorMessageDiscovery) {
		a.config = config
	}
}

func NewAggregatorMessageDiscovery(opts ...Option) (common.MessageDiscovery, error) {
	a := &AggregatorMessageDiscovery{
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
		messageCh:  make(chan protocol.CCVData),
		readerLock: &sync.Mutex{},
	}

	// Apply all options
	for _, opt := range opts {
		opt(a)
	}

	// Validata the configuration
	if err := a.validate(); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *AggregatorMessageDiscovery) validate() error {
	if a.config.PollInterval <= 0 {
		return errors.New("invalid poll interval")
	}

	if a.config.Timeout <= a.config.PollInterval {
		return errors.New("invalid timeout, needs to be greater then poll interval")
	}

	if a.aggregatorReader == nil {
		return errors.New("aggregator must be specified")
	}

	if a.logger == nil {
		return errors.New("logger must be specified")
	}

	if a.monitoring == nil {
		return errors.New("monitoring must be specified")
	}

	if a.storageSink == nil {
		return errors.New("storage must be specified")
	}

	return nil
}

func (a *AggregatorMessageDiscovery) Start(ctx context.Context) chan protocol.CCVData {
	go a.run(ctx)
	a.logger.Info("MessageDiscovery Started")

	// Return a channel that emits all messages discovered from the aggregator
	return a.messageCh
}

func (a *AggregatorMessageDiscovery) Close() error {
	close(a.stopCh)

	// Wait for processing to stop
	<-a.doneCh
	a.logger.Info("MessageDiscovery Stopped")
	return nil
}

func (a *AggregatorMessageDiscovery) Replay(ctx context.Context, start, end uint64) error {
	return nil
}

func (a *AggregatorMessageDiscovery) run(ctx context.Context) {
	defer close(a.doneCh)
	// Create a ticker based on the scan interval configured
	ticker := time.NewTicker(time.Duration(a.config.PollInterval) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("MessageDiscovery stopped due to context cancellation")
			return
		case <-a.stopCh:
			a.logger.Info("MessageDiscovery stopped due to stop signal")
			return
		case <-ticker.C:
			// Create a child context with a timeout to prevent a single call from blocking the entire discovery process
			readCtx, cancel := context.WithTimeout(ctx, time.Duration(a.config.Timeout)*time.Millisecond)

			// Consume the reader until there is no more data present from the aggregator
			// Aim is to allow for quick backfilling of data if needed.
			a.consumeReader(readCtx)
			cancel()
		}
	}
}

func (a *AggregatorMessageDiscovery) consumeReader(ctx context.Context) {
	// We can be in a situation where multiple calls to consumeReader are running concurrently due to the ticker.
	// This might happen during high load, or other situations where the ticker is running faster than the reader.
	// This lock is used to prevent concurrent access to the reader from the ticker.
	// If the lock is already held, the ticker channel will be blocked until the lock is released.
	// Subsequent ticks are then dropped, so there won't be any backpressure on the reader.
	a.readerLock.Lock()
	defer a.readerLock.Unlock()

	select {
	case <-ctx.Done():
		a.logger.Infof("Aggregator timed out, cancelling consumeReader")
		return
	default:
		for {
			found, err := a.callReader(ctx)
			if err != nil {
				a.logger.Errorw("Error calling Aggregator", "error", err)
				return
			}

			// If data is found, we'll try again after a small delay to prevent
			// duplicate data when processing faster than 1 second.
			// If no data is found, return and wait for the next tick.
			if !found {
				return
			}
		}
	}
}

func (a *AggregatorMessageDiscovery) callReader(ctx context.Context) (bool, error) {
	queryResponse, err := a.aggregatorReader.ReadCCVData(ctx)
	if err != nil {
		if a.isCircuitBreakerOpen() {
			a.logger.Errorw("Circuit breaker is open, skipping MessageDiscovery this tick")
			return false, nil
		}

		a.monitoring.Metrics().RecordScannerPollingErrorsCounter(ctx)
		a.logger.Errorw("Error reading VerificationResult from aggregator", "error", err)
		return false, err
	}

	a.logger.Debug("Called Aggregator")

	for _, response := range queryResponse {
		a.logger.Infof("Found new Message %s", response.Data.MessageID)

		// TODO: Update with message ingestion timestamp
		response.Data.Timestamp = time.Now()

		// Save the VerificationResult to the storage layer
		if err := a.storageSink.InsertCCVData(ctx, response.Data); err != nil {
			a.logger.Error("Error saving VerificationResult for MessageID %s to storage", response.Data.MessageID.String())
			continue
		}

		// Emit the Message into the message channel for downstream components to consume
		a.messageCh <- response.Data
	}

	// Return true if we processed any data, false if the slice was empty
	return len(queryResponse) > 0, nil
}

func (a *AggregatorMessageDiscovery) isCircuitBreakerOpen() bool {
	return a.aggregatorReader.GetDiscoveryCircuitBreakerState() == circuitbreaker.OpenState
}
