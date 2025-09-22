package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Scanner struct {
	readerDiscovery common.ReaderDiscovery
	config          Config
	storageWriter   common.IndexerStorageWriter
	lggr            logger.Logger
	ccvDataCh       chan types.CCVData
	stopCh          chan struct{}
	doneCh          chan struct{}
}

type Config struct {
	ScanInterval time.Duration
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
		ccvDataCh: make(chan types.CCVData, 1000),
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

	for {
		select {
		case <-ctx.Done():
			s.lggr.Info("Scanner stopped due to context cancellation")
			wg.Wait()
			return
		case <-s.stopCh:
			s.lggr.Info("Scanner stopped due to stop signal")
			wg.Wait()
			return
		case reader := <-readerDiscoveryCh:
			s.lggr.Info("Scanner discovered reader!")
			go s.handleReader(reader, &wg)
		case ccvData := <-s.ccvDataCh:
			if err := s.storageWriter.InsertCCVData(ctx, ccvData); err != nil {
				s.lggr.Errorw("Error inserting CCV data into indexer storage", "error", err)
			}
		}
	}
}

func (s *Scanner) handleReader(reader types.OffchainStorageReader, wg *sync.WaitGroup) {
	// Create a ticker based on the scan interval configured
	ticker := time.NewTicker(s.config.ScanInterval)
	wg.Add(1)
	defer ticker.Stop()
	defer wg.Done()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			queryResponse, err := reader.ReadCCVData(context.Background())
			s.lggr.Debug("Scanner read CCV data from reader")

			if err != nil {
				s.lggr.Errorw("Error reading CCV data from reader", "error", err)
				continue
			}

			for _, response := range queryResponse {
				s.lggr.Infow("Scanner populated CCV data channel with new data", "messageID", response.Data.MessageID)
				s.ccvDataCh <- response.Data
			}
		}
	}
}
