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

// PrimaryWriteNotifier allows the primary (priority-0) AggregatorMessageDiscovery to broadcast
// to all waiting secondary sources that its current write attempt has completed — whether it
// succeeded or failed.  Secondary sources select on WaitCh() alongside their own maximum-delay
// timer, so they proceed as soon as the primary finishes rather than burning the full delay when
// the primary fails early.
type PrimaryWriteNotifier struct {
	mu sync.Mutex
	ch chan struct{}
}

// NewPrimaryWriteNotifier creates a PrimaryWriteNotifier ready for use.
func NewPrimaryWriteNotifier() *PrimaryWriteNotifier {
	return &PrimaryWriteNotifier{ch: make(chan struct{})}
}

// Notify broadcasts that the primary has completed its write attempt.
// All goroutines currently waiting on WaitCh() are unblocked immediately.
func (n *PrimaryWriteNotifier) Notify() {
	n.mu.Lock()
	old := n.ch
	n.ch = make(chan struct{})
	n.mu.Unlock()
	close(old)
}

// WaitCh returns the channel to include in a select statement.
// The returned channel is closed (and therefore immediately selectable) when Notify is called next.
func (n *PrimaryWriteNotifier) WaitCh() <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.ch
}

type AggregatorMessageDiscovery struct {
	logger            logger.Logger
	config            config.DiscoveryConfig
	aggregatorReader  *readers.ResilientReader
	registry          *registry.VerifierRegistry
	storageSink       common.IndexerStorage
	monitoring        common.IndexerMonitoring
	timeProvider      ccvcommon.TimeProvider
	messageCh         chan common.VerifierResultWithMetadata
	doneCh            chan struct{}
	wg                sync.WaitGroup
	cancelFunc        context.CancelFunc
	discoveryPriority int
	// primaryWriteNotifier is shared across all AggregatorMessageDiscovery instances in a
	// multi-source setup.  The primary (priority 0) calls Notify() after each write attempt;
	// secondary sources call WaitCh() in their delay select so they unblock as soon as the
	// primary is done rather than sleeping the full delay when the primary fails.
	primaryWriteNotifier *PrimaryWriteNotifier
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

func WithDiscoveryPriority(discoveryPriority int) Option {
	return func(a *AggregatorMessageDiscovery) {
		a.discoveryPriority = discoveryPriority
	}
}

// WithPrimaryWriteNotifier wires the shared PrimaryWriteNotifier into a discovery instance.
// Pass the same notifier to all sources in a multi-source setup:
//   - the primary (priority 0) will call Notify() after each write attempt via defer
//   - secondary sources (priority > 0) will call WaitCh() so their delay select can
//     short-circuit as soon as the primary finishes, avoiding redundant waits when the
//     primary aggregator is down.
//
// Passing nil is safe and disables the coordination (single-source or opt-out).
func WithPrimaryWriteNotifier(notifier *PrimaryWriteNotifier) Option {
	return func(a *AggregatorMessageDiscovery) {
		a.primaryWriteNotifier = notifier
	}
}

func NewAggregatorMessageDiscovery(opts ...Option) (common.MessageDiscovery, error) {
	a := &AggregatorMessageDiscovery{
		messageCh: make(chan common.VerifierResultWithMetadata),
		doneCh:    make(chan struct{}),
	}

	// Apply all options
	for _, opt := range opts {
		opt(a)
	}

	// Validate the configuration
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

	if a.timeProvider == nil {
		return errors.New("time provider must be specified")
	}

	return nil
}

func (a *AggregatorMessageDiscovery) Start(ctx context.Context) chan common.VerifierResultWithMetadata {
	childCtx, cancelFunc := context.WithCancel(ctx)
	a.wg.Add(1)
	go a.run(childCtx)
	a.cancelFunc = cancelFunc
	a.logger.Info("MessageDiscovery Started")

	// Return a channel that emits all messages discovered from the aggregator
	return a.messageCh
}

func (a *AggregatorMessageDiscovery) Close() error {
	a.cancelFunc()
	defer close(a.messageCh)
	close(a.doneCh)
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
			// Stagger timeouts across discovery instances so they don't all time out
			// simultaneously when the aggregator is under pressure.
			readCtx, cancel := context.WithTimeout(ctx, time.Duration(a.config.Timeout)*time.Millisecond+(time.Duration(a.discoveryPriority)*5*time.Second))

			// Consume the reader until there is no more data present from the aggregator
			// Aim is to allow for quick backfilling of data if needed.
			a.consumeReader(readCtx)
			cancel()
		}
	}
}

func (a *AggregatorMessageDiscovery) consumeReader(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	for {
		if ctx.Err() != nil {
			a.logger.Infof("Aggregator timed out, cancelling consumeReader")
			return
		}
		found, err := a.callReader(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
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

func (a *AggregatorMessageDiscovery) callReader(ctx context.Context) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	// When this is the primary source (priority 0) and a notifier is configured,
	// always signal completion on return — whether the write succeeded, failed, or we
	// returned early due to an error.  This unblocks any secondary sources that are waiting
	// in their delay select, preventing redundant full-delay waits when the primary is down.
	if a.discoveryPriority == 0 && a.primaryWriteNotifier != nil {
		defer a.primaryWriteNotifier.Notify()
	}

	startingSequence, ableToSetSinceValue := a.aggregatorReader.GetSinceValue()
	// We reset the since value when after reading the data from aggregator but we fail to persist the data.
	// TODO: If we ever support discovery where we can't set the since value, we will need to review what it means for this particular source to not reset the since value.
	resetSinceValue := func() {
		if ableToSetSinceValue {
			a.aggregatorReader.SetSinceValue(startingSequence)
		}
	}
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
	a.monitoring.Metrics().RecordIndexerMessageDiscoveryLatency(ctx, time.Since(discoveryStartTime))

	a.logger.Debug("Called Aggregator")

	ingestionTimestamp := a.timeProvider.GetTime()
	messages := []common.MessageWithMetadata{}
	persistedVerifications := []common.VerifierResultWithMetadata{}
	allVerifications := []common.VerifierResultWithMetadata{}
	for _, response := range queryResponse {
		a.logger.Infow("Found Message", "messageID", response.Data.MessageID, "verifierSourceAddress", response.Data.VerifierSourceAddress)

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
				Status:             common.MessageProcessing,
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

	// We use a discovery priority for the multi-source scenario where we want to ensure data
	// consistency.  The delay is applied after reading so the aggregator is queried immediately,
	// but persisting and channel emission are deferred, giving higher-priority sources time to
	// persist first.
	//
	// Secondary sources (priority > 0) select on the primary's WaitCh() alongside the
	// timer.  If the primary finishes its write attempt (success or failure) before the timer
	// fires, the secondary unblocks immediately instead of waiting the full delay.  This avoids
	// the redundant delay that occurs when the primary aggregator is unresponsive.
	delay := time.Duration(a.discoveryPriority) * 5 * time.Second
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()

		// primaryWrittenCh is nil when no notifier is configured; a nil channel in a select
		// case is never ready, so the behavior gracefully degrades to timer-only.
		var primaryWrittenCh <-chan struct{}
		if a.primaryWriteNotifier != nil {
			primaryWrittenCh = a.primaryWriteNotifier.WaitCh()
		}

		select {
		case <-ctx.Done():
			resetSinceValue()
			return false, ctx.Err()
		case <-primaryWrittenCh: // primary finished its write attempt (success or failure)
		case <-timer.C: // maximum wait elapsed; proceed regardless
		}
	}

	if len(messages) > 0 || len(persistedVerifications) > 0 {
		if err := a.persistBatch(ctx, messages, persistedVerifications, ableToSetSinceValue); err != nil {
			a.logger.Warnw("Unable to persist discovery batch, will retry", "error", err)
			resetSinceValue()
			return false, err
		}
	}

	for _, verifierResultWithMetadata := range allVerifications {
		// Use a context-aware send so that if the context is canceled while
		// enqueueMessages has already exited (leaving messageCh with no reader), we return
		// cleanly instead of blocking forever and preventing wg.Done() from being called.
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case a.messageCh <- verifierResultWithMetadata:
		}
		// Record the channel size after send so the metric reflects the current backlog.
		a.monitoring.Metrics().RecordVerificationRecordChannelSizeGauge(ctx, int64(len(a.messageCh)))
		a.monitoring.Metrics().RecordTimeToIndex(ctx, time.Since(verifierResultWithMetadata.Metadata.AttestationTimestamp), "aggregator")
	}

	// Return true if we processed any data, false if the slice was empty
	return len(queryResponse) > 0, nil
}

func (a *AggregatorMessageDiscovery) persistBatch(
	ctx context.Context,
	messages []common.MessageWithMetadata,
	verifications []common.VerifierResultWithMetadata,
	ableToSetSinceValue bool,
) error {
	sequenceNumber := common.SequenceNumberNotSupported
	if ableToSetSinceValue {
		if currentSequence, supports := a.aggregatorReader.GetSinceValue(); supports {
			sequenceNumber = int(currentSequence)
		}
	}

	return a.storageSink.PersistDiscoveryBatch(ctx, common.DiscoveryBatch{
		Messages:          messages,
		Verifications:     verifications,
		DiscoveryLocation: a.config.Address,
		SequenceNumber:    sequenceNumber,
	})
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
