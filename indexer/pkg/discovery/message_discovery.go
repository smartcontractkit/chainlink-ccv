package discovery

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/failsafe-go/failsafe-go/circuitbreaker"

	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ common.MessageDiscovery = (*AggregatorMessageDiscovery)(nil)

type AggregatorMessageDiscovery struct {
	logger           logger.Logger
	config           config.DiscoveryConfig
	aggregatorReader *readers.ResilientReader
	registry         *registry.VerifierRegistry
	storageSink      common.IndexerStorage
	monitoring       common.IndexerMonitoring
	timeProvider     ccvcommon.TimeProvider
	messageCh        chan common.VerifierResultWithMetadata
	readerLock       *sync.Mutex
	wg               sync.WaitGroup
	cancelFunc       context.CancelFunc
}

type Option func(*AggregatorMessageDiscovery)

func WithAggregator(aggregator *readers.ResilientReader) Option {
	return func(a *AggregatorMessageDiscovery) {
		a.aggregatorReader = aggregator
	}
}

func WithRegistry(registry *registry.VerifierRegistry) Option {
	return func(a *AggregatorMessageDiscovery) {
		a.registry = registry
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

func WithTimeProvider(timeProvider ccvcommon.TimeProvider) Option {
	return func(a *AggregatorMessageDiscovery) {
		a.timeProvider = timeProvider
	}
}

func NewAggregatorMessageDiscovery(opts ...Option) (common.MessageDiscovery, error) {
	a := &AggregatorMessageDiscovery{
		messageCh:  make(chan common.VerifierResultWithMetadata),
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

	if a.registry == nil {
		return errors.New("registry must be specified")
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

func (a *AggregatorMessageDiscovery) Start(ctx context.Context) chan common.VerifierResultWithMetadata {
	childCtx, cancelFunc := context.WithCancel(ctx)
	a.wg.Add(2)
	go a.run(childCtx)
	go a.updateSequenceNumber(childCtx)
	a.cancelFunc = cancelFunc
	a.logger.Info("MessageDiscovery Started")

	// Return a channel that emits all messages discovered from the aggregator
	return a.messageCh
}

// sampleChannelSize periodically records the current length of the discovery
// message channel so the verification record channel size gauge reflects both
// sends and receives.
func (a *AggregatorMessageDiscovery) sampleChannelSize(ctx context.Context) {
	defer a.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("sampleChannelSize stopped due to context cancellation")
			return
		case <-ticker.C:
			// Use background or provided ctx; keep it tied to lifecycle so metrics shutdown works with parent.
			a.monitoring.Metrics().RecordVerificationRecordChannelSizeGauge(ctx, int64(len(a.messageCh)))
		}
	}
}

func (a *AggregatorMessageDiscovery) Close() error {
	a.cancelFunc()
	a.wg.Wait()
	a.logger.Info("MessageDiscovery Stopped")
	return nil
}

func (a *AggregatorMessageDiscovery) Replay(ctx context.Context, start, end uint64) error {
	return nil
}

func (a *AggregatorMessageDiscovery) run(ctx context.Context) {
	defer a.wg.Done()

	// Create a ticker based on the scan interval configured
	ticker := time.NewTicker(time.Duration(a.config.PollInterval) * time.Millisecond)
	defer ticker.Stop()

	// Ticker to sample the discovery message channel size periodically
	sampleTicker := time.NewTicker(time.Second)
	defer sampleTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("MessageDiscovery stopped due to context cancellation")
			return
		case <-sampleTicker.C:
			// Use background or provided ctx; keep it tied to lifecycle so metrics shutdown works with parent.
			a.monitoring.Metrics().RecordVerificationRecordChannelSizeGauge(ctx, int64(len(a.messageCh)))

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

func (a *AggregatorMessageDiscovery) updateSequenceNumber(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("updateSequenceNumber stopped due to context cancellation")
			return
		case <-ticker.C:
			latestSequenceNumber, supports := a.aggregatorReader.GetSinceValue()
			if !supports {
				a.logger.Warnw("unable to update sequence number as reader does not support this.", "discoveryLocation", a.config.Address)
			}

			if err := a.storageSink.UpdateDiscoverySequenceNumber(ctx, a.config.Address, int(latestSequenceNumber)); err != nil {
				a.logger.Errorf("unable to update sequence number: %w", err)
			}
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
	startingSequence, ableToSetSinceValue := a.aggregatorReader.GetSinceValue()
	var queryResponse []protocol.QueryResponse
	discoveryStartTime := time.Now()
	queryResponse, err := a.aggregatorReader.ReadCCVData(ctx)
	if err != nil {
		if a.isCircuitBreakerOpen() {
			a.monitoring.Metrics().RecordCircuitBreakerStatus(ctx, true)
			a.logger.Errorw("Circuit breaker is open, skipping MessageDiscovery this tick")
			return false, nil
		}
		a.monitoring.Metrics().RecordScannerPollingErrorsCounter(ctx)
		a.logger.Errorw("Error reading VerificationResult from aggregator", "error", err)
		return false, err
	}

	a.logger.Debug("Called Aggregator")

	ingestionTimestamp := a.timeProvider.GetTime()
	messages := []common.MessageWithMetadata{}
	persistedVerifications := []common.VerifierResultWithMetadata{}
	allVerifications := []common.VerifierResultWithMetadata{}
	for _, response := range queryResponse {
		a.logger.Infof("Found new Message %s", response.Data.MessageID)

		verifierResultWithMetadata := common.VerifierResultWithMetadata{
			VerifierResult: response.Data,
			Metadata: common.VerifierResultMetadata{
				IngestionTimestamp:   ingestionTimestamp,
				AttestationTimestamp: response.Data.Timestamp,
				VerifierName:         a.registry.GetVerifierNameFromAddress(response.Data.VerifierSourceAddress),
			},
		}

		message := common.MessageWithMetadata{
			Message: response.Data.Message,
			Metadata: common.MessageMetadata{
				IngestionTimestamp: ingestionTimestamp,
			},
		}

		// If the verification is valid on-chain we'll persist it.
		if !a.isDiscoveryOnly(verifierResultWithMetadata) {
			persistedVerifications = append(persistedVerifications, verifierResultWithMetadata)
		}

		messages = append(messages, message)
		allVerifications = append(allVerifications, verifierResultWithMetadata)
	}
	a.monitoring.Metrics().RecordIndexerMessageDiscoveryLatency(ctx, time.Since(discoveryStartTime))

	// Save all messages we've seen from the discovery source, if we're unable to persist them.
	// We'll set the sequence value on the reader back to it's original value.
	// This means we won't continue ingesting new messages until these ones are saved.
	//
	// This ensures that we won't miss a message.
	if err := a.storageSink.BatchInsertMessages(ctx, messages); err != nil {
		a.logger.Warn("Unable to save messages to storage, will retry")
		if ableToSetSinceValue {
			a.aggregatorReader.SetSinceValue(startingSequence)
		}
		return false, err
	}

	if len(persistedVerifications) > 0 {
		err := a.storageSink.BatchInsertCCVData(ctx, persistedVerifications)
		if err != nil {
			a.logger.Warn("Unable to save verifications to storage, will retry")
			if ableToSetSinceValue {
				a.aggregatorReader.SetSinceValue(startingSequence)
			}
			return false, err
		}
	}

	for _, verifierResultWithMetadata := range allVerifications {
		// Emit the Message into the message channel for downstream components to consume
		a.messageCh <- verifierResultWithMetadata
		// Record the channel size after send so the metric reflects the current backlog.
		// Use the same context used for the call so the metric respects cancellation.
		a.monitoring.Metrics().RecordVerificationRecordChannelSizeGauge(ctx, int64(len(a.messageCh)))
		a.monitoring.Metrics().RecordTimeToIndex(ctx, time.Since(verifierResultWithMetadata.Metadata.AttestationTimestamp), "aggregator")
	}

	// Return true if we processed any data, false if the slice was empty
	return len(queryResponse) > 0, nil
}

func (a *AggregatorMessageDiscovery) isCircuitBreakerOpen() bool {
	return a.aggregatorReader.GetDiscoveryCircuitBreakerState() == circuitbreaker.OpenState
}

func (a *AggregatorMessageDiscovery) isDiscoveryOnly(verifierResult common.VerifierResultWithMetadata) bool {
	// Sanity Check: This should never happen, but in case of a discovery message that is smaller then the version
	// This can never be valid on-chain and therefore MUST be a discovery only message.
	if len(verifierResult.VerifierResult.CCVData) <= protocol.MessageDiscoveryVersionLength {
		a.logger.Infow("Discovery only message, we will not persist the CCVData", "messageID", verifierResult.VerifierResult.MessageID)
		return true
	}

	// If the 4-byte version at the start of the data is equal to the message discovery version
	// This verification is invalid on-chain and we won't persist the verification.
	version := verifierResult.VerifierResult.CCVData[:protocol.MessageDiscoveryVersionLength]
	if bytes.Equal(version, protocol.MessageDiscoveryVersion) {
		a.logger.Infow("Discovery only message, we will not persist the CCVData", "messageID", verifierResult.VerifierResult.MessageID)
		return true
	}

	// All other circumstances, it's a valid verification.
	return false
}
