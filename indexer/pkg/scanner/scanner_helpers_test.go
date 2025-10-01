package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/discovery"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// testSetup contains all the components needed for scanner tests.
type testSetup struct {
	Scanner   *Scanner
	Logger    logger.Logger
	Monitor   common.IndexerMonitoring
	Storage   common.IndexerStorage
	Discovery common.ReaderDiscovery
	Context   context.Context
	Cancel    context.CancelFunc
}

// Cleanup stops the scanner and cancels the context.
func (ts *testSetup) Cleanup() {
	if ts.Scanner != nil {
		ts.Scanner.Stop()
	}
	if ts.Cancel != nil {
		ts.Cancel()
	}
}

// setupScannerTest creates a complete test setup with default configuration.
func setupScannerTest(t *testing.T) *testSetup {
	t.Helper()
	return setupScannerTestWithConfig(t, Config{
		ScanInterval:   50 * time.Millisecond,
		MetricInterval: 100 * time.Millisecond,
		ReaderTimeout:  500 * time.Millisecond,
	})
}

// setupScannerTestWithConfig creates a test setup with custom configuration.
func setupScannerTestWithConfig(t *testing.T, config Config) *testSetup {
	t.Helper()
	return setupScannerTestWithTimeout(t, config, 5*time.Second)
}

// setupScannerTestWithTimeout creates a test setup with custom timeout.
func setupScannerTestWithTimeout(t *testing.T, config Config, timeout time.Duration) *testSetup {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()
	store := storage.NewInMemoryStorage(lggr, mon)
	disc := discovery.NewStaticDiscovery([]protocol.OffchainStorageReader{})

	scanner := NewScanner(
		WithLogger(lggr),
		WithMonitoring(mon),
		WithStorageWriter(store),
		WithReaderDiscovery(disc),
		WithConfig(config),
	)

	return &testSetup{
		Scanner:   scanner,
		Logger:    lggr,
		Monitor:   mon,
		Storage:   store,
		Discovery: disc,
		Context:   ctx,
		Cancel:    cancel,
	}
}

// setupScannerTestNoTimeout creates a test setup without a timeout context.
func setupScannerTestNoTimeout(t *testing.T, config Config) *testSetup {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()
	store := storage.NewInMemoryStorage(lggr, mon)
	disc := discovery.NewStaticDiscovery([]protocol.OffchainStorageReader{})

	scanner := NewScanner(
		WithLogger(lggr),
		WithMonitoring(mon),
		WithStorageWriter(store),
		WithReaderDiscovery(disc),
		WithConfig(config),
	)

	return &testSetup{
		Scanner:   scanner,
		Logger:    lggr,
		Monitor:   mon,
		Storage:   store,
		Discovery: disc,
		Context:   ctx,
		Cancel:    cancel,
	}
}

// defaultTestConfig returns the standard configuration used in most tests.
func defaultTestConfig() Config {
	return Config{
		ScanInterval:   50 * time.Millisecond,
		MetricInterval: 100 * time.Millisecond,
		ReaderTimeout:  500 * time.Millisecond,
	}
}

// fastScannerTestConfig returns a configuration with faster intervals for race testing.
func fastScannerTestConfig() Config {
	return Config{
		ScanInterval:   1 * time.Millisecond,
		MetricInterval: 50 * time.Millisecond,
		ReaderTimeout:  200 * time.Millisecond,
	}
}

// standardTestConfig returns a configuration with standard timing.
func standardTestConfig() Config {
	return Config{
		ScanInterval:   20 * time.Millisecond,
		MetricInterval: 100 * time.Millisecond,
		ReaderTimeout:  200 * time.Millisecond,
	}
}
