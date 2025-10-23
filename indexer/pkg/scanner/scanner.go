package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/failsafe-go/failsafe-go/circuitbreaker"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Scanner struct {
	readerDiscovery common.ReaderDiscovery
	config          Config
	storageWriter   common.IndexerStorageWriter
	lggr            logger.Logger
	monitoring      common.IndexerMonitoring
	mu              sync.Mutex
	activeReaders   int64
	ccvDataCh       chan protocol.CCVData
	stopCh          chan struct{}
	doneCh          chan struct{}
	// Reader locks to prevent concurrent access to the same reader
	readerLocks sync.Map // map[protocol.OffchainStorageReader]*sync.Mutex
}

type Config struct {
	ScanInterval   time.Duration
	MetricInterval time.Duration
	ReaderTimeout  time.Duration
}

// Option is the functional option type for Scanner.
type Option func(*Scanner)

// WithReaderDiscovery sets the reader discovery method.
func WithReaderDiscovery(readerDiscovery common.ReaderDiscovery) Option {
	return func(s *Scanner) {
		s.readerDiscovery = readerDiscovery
	}
}

// WithLogger sets the logger.
func WithLogger(lggr logger.Logger) Option {
	return func(s *Scanner) {
		s.lggr = lggr
	}
}

// WithMonitoring sets the monitoring.
func WithMonitoring(monitoring common.IndexerMonitoring) Option {
	return func(s *Scanner) {
		s.monitoring = monitoring
	}
}

// WithConfig sets the scanner configuration.
func WithConfig(config Config) Option {
	return func(s *Scanner) {
		s.config = config
	}
}

func WithStorageWriter(storageWriter common.IndexerStorageWriter) Option {
	return func(s *Scanner) {
		s.storageWriter = storageWriter
	}
}

// NewScanner creates a new Scanner with the given options.
func NewScanner(opts ...Option) *Scanner {
	s := &Scanner{
		ccvDataCh: make(chan protocol.CCVData),
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}

	// Apply all options
	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (s *Scanner) Start(ctx context.Context) {
	go s.run(ctx)
	s.lggr.Info("Scanner started")
}

func (s *Scanner) Stop() {
	close(s.stopCh)

	// Wait for processing to stop
	<-s.doneCh
	s.lggr.Info("Scanner stopped")
}

// Main loop for the Scanner.
func (s *Scanner) run(ctx context.Context) {
	defer close(s.doneCh)
	var wg sync.WaitGroup

	s.lggr.Info("Scanner discovering readers")
	readerDiscoveryCh := s.readerDiscovery.Run(ctx)

	// Create a ticker for periodic metric recording
	metricTicker := time.NewTicker(s.config.MetricInterval)
	defer metricTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.lggr.Info("Scanner stopped due to context cancellation")
			s.close(ctx, &wg)
			return
		case <-s.stopCh:
			s.lggr.Info("Scanner stopped due to stop signal")
			s.close(ctx, &wg)
			return
		case reader := <-readerDiscoveryCh:
			s.lggr.Info("Scanner discovered reader!")
			s.mu.Lock()
			s.activeReaders++
			s.mu.Unlock()
			s.monitoring.Metrics().RecordActiveReadersGauge(ctx, s.activeReaders)
			wg.Add(1)
			go s.handleReader(ctx, reader, &wg)
		case ccvData := <-s.ccvDataCh:
			// For now, we'll just update the timestamp to be the timestamp of ingestion
			ccvData.Timestamp = time.Now().Unix()
			// Record channel size after consuming data
			s.monitoring.Metrics().RecordVerificationRecordChannelSizeGauge(ctx, int64(len(s.ccvDataCh)))
			if err := s.storageWriter.InsertCCVData(ctx, ccvData); err != nil {
				s.lggr.Errorw("Error inserting CCV data into indexer storage", "error", err)
			}
		case <-metricTicker.C:
			// Periodically record channel size for monitoring
			s.monitoring.Metrics().RecordVerificationRecordChannelSizeGauge(ctx, int64(len(s.ccvDataCh)))
		}
	}
}

func (s *Scanner) close(ctx context.Context, wg *sync.WaitGroup) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	for {
		select {
		case <-done:
			return
		case ccvData := <-s.ccvDataCh:
			// Continue processing data while waiting for goroutines to finish
			s.monitoring.Metrics().RecordVerificationRecordChannelSizeGauge(ctx, int64(len(s.ccvDataCh)))
			if err := s.storageWriter.InsertCCVData(ctx, ccvData); err != nil {
				s.lggr.Errorw("Error inserting CCV data into indexer storage", "error", err)
			}
		}
	}
}

func (s *Scanner) handleReader(ctx context.Context, reader protocol.OffchainStorageReader, wg *sync.WaitGroup) {
	defer wg.Done()
	// Create a ticker based on the scan interval configured
	ticker := time.NewTicker(s.config.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			// Create a child context with a timeout to prevent a single call from blocking the entire reader.
			readerCtx, cancel := context.WithTimeout(ctx, s.config.ReaderTimeout)

			// Consume the reader until there is no more data present from the reader.
			// Aim is to allow for quick backfilling of data if needed.
			s.consumeReader(readerCtx, reader)
			cancel()

			// Some readers support disconnection in certain situations, such as backfilling.
			// If the reader should be disconnected after being consumed, finish the loop and drop the reader.
			// The context passed here is the parent context, which is not timed out so we can publish metrics if needed.
			if s.shouldDisconnect(ctx, reader) {
				return
			}
		}
	}
}

func (s *Scanner) shouldDisconnect(ctx context.Context, reader protocol.OffchainStorageReader) bool {
	// Check if this reader supports disconnection
	if disconnectableReader, ok := reader.(protocol.DisconnectableReader); ok {
		if disconnectableReader.ShouldDisconnect() {
			s.lggr.Infow("Reader signaled disconnection, removing from scanner")
			s.mu.Lock()
			s.activeReaders--
			activeCount := s.activeReaders
			s.mu.Unlock()
			s.monitoring.Metrics().RecordActiveReadersGauge(ctx, activeCount)

			return true
		}
	}

	// Either the reader doesn't support disconnection, or it didn't signal disconnection.
	return false
}

// getReaderLock returns a mutex for the given reader to prevent concurrent access.
func (s *Scanner) getReaderLock(reader protocol.OffchainStorageReader) *sync.Mutex {
	lock, _ := s.readerLocks.LoadOrStore(reader, &sync.Mutex{})
	mutex, ok := lock.(*sync.Mutex)
	if !ok {
		s.lggr.Errorw("Failed to assert type *sync.Mutex for reader lock, returning empty mutex. This should never happen")
		return &sync.Mutex{}
	}

	return mutex
}

func (s *Scanner) consumeReader(ctx context.Context, reader protocol.OffchainStorageReader) {
	// We can be in a situation where multiple calls to consumeReader are running concurrently due to the ticker.
	// This might happen during backfilling, high load, or other situations where the ticker is running faster than the reader.
	// This lock is used to prevent concurrent access to the reader from the ticker.
	// If the lock is already held, the ticker channel will be blocked until the lock is released.
	// Subsequent ticks are then dropped, so there won't be any backpressure on the reader.
	readerLock := s.getReaderLock(reader)
	readerLock.Lock()
	defer readerLock.Unlock()

	select {
	case <-ctx.Done():
		s.lggr.Infof("Reader timed out, cancelling consumeReader")
		return
	default:
		for {
			found, err := s.callReader(ctx, reader)
			if err != nil {
				s.lggr.Errorw("Error calling reader", "error", err)
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

func (s *Scanner) callReader(ctx context.Context, reader protocol.OffchainStorageReader) (bool, error) {
	queryResponse, err := reader.ReadCCVData(ctx)
	if err != nil {
		if s.isCircuitBreakerOpen(reader) {
			s.lggr.Errorw("Circuit breaker is open, skipping reader")
			return false, nil
		}

		s.monitoring.Metrics().RecordScannerPollingErrorsCounter(ctx)
		s.lggr.Errorw("Error reading VerificationResult from reader", "error", err)
		return false, err
	}

	s.lggr.Debug("Scanner read VerificationResult from reader")

	for _, response := range queryResponse {
		s.lggr.Infof("Populated VerificationResult channel with new data messageID %s", response.Data.MessageID)
		s.ccvDataCh <- response.Data
		// Record channel size after adding data
		s.monitoring.Metrics().RecordVerificationRecordChannelSizeGauge(ctx, int64(len(s.ccvDataCh)))
	}

	// Return true if we processed any data, false if the slice was empty
	return len(queryResponse) > 0, nil
}

func (s *Scanner) isCircuitBreakerOpen(reader protocol.OffchainStorageReader) bool {
	if resilientReader, ok := reader.(*readers.ResilientReader); ok {
		return resilientReader.GetCircuitBreakerState() == circuitbreaker.OpenState
	}

	return false
}
