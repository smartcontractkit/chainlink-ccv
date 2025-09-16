package storageaccess

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// StorageEntry represents an internal storage entry for organizing CCV data with timestamp ordering.
// This encapsulates the metadata needed for timestamp-based querying
// while keeping the storage implementation details clean and maintainable.
type StorageEntry struct {
	CCVData        types.CCVData
	CreatedAt      int64
	InsertionOrder int64
}

// Less enables sorting by (CreatedAt, InsertionOrder).
func (e StorageEntry) Less(other StorageEntry) bool {
	if e.CreatedAt != other.CreatedAt {
		return e.CreatedAt < other.CreatedAt
	}
	return e.InsertionOrder < other.InsertionOrder
}

// TimeProvider is a function type for providing current time (for testing).
type TimeProvider func() int64

// DefaultTimeProvider returns current time in microseconds since epoch.
func DefaultTimeProvider() int64 {
	return time.Now().UnixMicro()
}

// InMemoryOffchainStorage implements both OffchainStorageWriter and OffchainStorageReader
// for testing and development. Uses a list of StorageEntry objects to store CCV data
// with timestamp ordering. Data is kept sorted by (CreatedAt, InsertionOrder) for efficient
// timestamp-based queries with deterministic ordering.
type InMemoryOffchainStorage struct {
	lggr                 logger.Logger
	timeProvider         TimeProvider
	storedCh             chan struct{}
	storage              []StorageEntry
	destChainSelectors   []types.ChainSelector
	sourceChainSelectors []types.ChainSelector
	insertionCounter     int64
	limit                uint64
	offset               uint64
	nextTimestamp        int64
	mu                   sync.RWMutex
}

// NewInMemoryOffchainStorage creates a new in-memory offchain storage with some default parameters.
func NewInMemoryOffchainStorage(lggr logger.Logger) *InMemoryOffchainStorage {
	return NewInMemoryOffchainStorageWithTimeProvider(lggr, DefaultTimeProvider, nil, nil, 10, 0, time.Now().Unix())
}

// NewInMemoryOffchainStorageWithTimeProvider creates a new in-memory offchain storage with custom time provider.
func NewInMemoryOffchainStorageWithTimeProvider(
	lggr logger.Logger,
	timeProvider TimeProvider,
	destChainSelectors []types.ChainSelector,
	sourceChainSelectors []types.ChainSelector,
	limit uint64,
	offset uint64,
	startTimestamp int64,
) *InMemoryOffchainStorage {
	return &InMemoryOffchainStorage{
		storage:              make([]StorageEntry, 0),
		insertionCounter:     0,
		timeProvider:         timeProvider,
		lggr:                 lggr,
		storedCh:             make(chan struct{}, 100),
		destChainSelectors:   destChainSelectors,
		sourceChainSelectors: sourceChainSelectors,
		nextTimestamp:        startTimestamp,
		limit:                limit,
		offset:               offset,
	}
}

// CreateReaderOnly creates a read-only view of the storage that only implements OffchainStorageReader.
func CreateReaderOnly(storage *InMemoryOffchainStorage) types.OffchainStorageReader {
	return &ReaderOnlyView{storage: storage}
}

// CreateWriterOnly creates a write-only view of the storage that only implements OffchainStorageWriter.
func CreateWriterOnly(storage *InMemoryOffchainStorage) types.OffchainStorageWriter {
	return &WriterOnlyView{storage: storage}
}

// WaitForStore waits for data to be stored or context to be canceled.
func (s *InMemoryOffchainStorage) WaitForStore(ctx context.Context) error {
	select {
	case <-s.storedCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WriteCCVData stores multiple CCV data entries in the offchain storage.
func (s *InMemoryOffchainStorage) WriteCCVData(ctx context.Context, ccvDataList []types.CCVData) error {
	if len(ccvDataList) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	createdAt := s.timeProvider() // Storage determines when data was stored
	s.lggr.Debugw("Storing CCV data",
		"count", len(ccvDataList),
		"createdAt", createdAt,
	)

	for _, ccvData := range ccvDataList {
		// Create storage entry with timestamp and ordering
		entry := StorageEntry{
			CreatedAt:      createdAt,
			InsertionOrder: s.insertionCounter,
			CCVData:        ccvData,
		}
		s.storage = append(s.storage, entry)
		s.insertionCounter++
	}

	// Keep storage sorted by (CreatedAt, InsertionOrder)
	sort.Slice(s.storage, func(i, j int) bool {
		return s.storage[i].Less(s.storage[j])
	})

	s.lggr.Debugw("Stored CCV data",
		"count", len(ccvDataList),
		"totalStored", len(s.storage),
	)

	// Notify that data was stored
	select {
	case s.storedCh <- struct{}{}:
	default:
		// Channel full, ignore
	}

	return nil
}

// ReadCCVData fetches CCV data by timestamp.
func (s *InMemoryOffchainStorage) ReadCCVData(ctx context.Context) ([]types.QueryResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.lggr.Debugw("Querying CCV data by timestamp",
		"destChains", s.destChainSelectors,
		"startTimestamp", s.nextTimestamp,
		"sourceChains", s.sourceChainSelectors,
		"limit", s.limit,
		"offset", s.offset,
		"totalEntries", len(s.storage),
	)

	// Filter data by timestamp and other criteria
	filteredEntries := make([]StorageEntry, 0, len(s.storage))
	for _, entry := range s.storage {
		// Skip entries before start_timestamp
		if entry.CreatedAt < s.nextTimestamp {
			continue
		}

		if len(s.destChainSelectors) > 0 {
			// Filter by destination chain
			found := false
			for _, destChain := range s.destChainSelectors {
				if entry.CCVData.DestChainSelector == destChain {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Filter by source chain if specified
		if len(s.sourceChainSelectors) > 0 {
			found := false
			for _, sourceChain := range s.sourceChainSelectors {
				if entry.CCVData.SourceChainSelector == sourceChain {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		filteredEntries = append(filteredEntries, entry)
	}

	// Apply offset and limit
	totalFiltered := uint64(len(filteredEntries))
	var paginatedEntries []StorageEntry
	if s.offset < totalFiltered {
		end := s.offset + s.limit
		if end > totalFiltered {
			end = totalFiltered
		}
		paginatedEntries = filteredEntries[s.offset:end]
	}

	// Prepare result data
	resultData := make([]types.QueryResponse, len(paginatedEntries))
	for i, entry := range paginatedEntries {
		resultData[i] = types.QueryResponse{
			Data:      entry.CCVData,
			Timestamp: &entry.CreatedAt,
		}
	}

	// Determine pagination metadata
	s.offset += uint64(len(resultData))

	return resultData, nil
}

// GetAllCCVData retrieves all CCV data for a verifier (for testing/debugging).
func (s *InMemoryOffchainStorage) GetAllCCVData(verifierAddress []byte) ([]types.CCVData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]types.CCVData, 0, len(s.storage))
	for _, entry := range s.storage {
		if string(entry.CCVData.SourceVerifierAddress) == string(verifierAddress) {
			result = append(result, entry.CCVData)
		}
	}

	return result, nil
}

// ReadCCVDataByMessageID retrieves CCV data by message ID (for testing/debugging).
func (s *InMemoryOffchainStorage) ReadCCVDataByMessageID(messageID types.Bytes32) (*types.CCVData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, entry := range s.storage {
		if string(entry.CCVData.MessageID[:]) == string(messageID[:]) {
			return &entry.CCVData, nil
		}
	}

	return nil, fmt.Errorf("CCV data not found for message ID: %x", messageID)
}

// GetStats returns storage statistics (for testing/debugging).
func (s *InMemoryOffchainStorage) GetStats() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := make(map[string]any)
	totalEntries := len(s.storage)
	verifierCounts := make(map[string]int)

	for _, entry := range s.storage {
		verifierKey := string(entry.CCVData.SourceVerifierAddress)
		verifierCounts[verifierKey]++
	}

	stats["totalEntries"] = totalEntries
	stats["verifierCounts"] = verifierCounts
	stats["verifierCount"] = len(verifierCounts)

	return stats
}

// Clear removes all stored data (for testing).
func (s *InMemoryOffchainStorage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.storage = make([]StorageEntry, 0)
	s.insertionCounter = 0
	s.lggr.Debugw("Cleared all stored data")
}

// GetTotalCount returns the total number of CCV data entries stored (for testing).
func (s *InMemoryOffchainStorage) GetTotalCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.storage)
}

// Helper methods for testing and debugging (not part of the interface).
func (s *InMemoryOffchainStorage) ListDestChains() []types.ChainSelector {
	s.mu.RLock()
	defer s.mu.RUnlock()

	destChains := make(map[types.ChainSelector]bool)
	for _, entry := range s.storage {
		destChains[entry.CCVData.DestChainSelector] = true
	}

	result := make([]types.ChainSelector, 0, len(destChains))
	for destChain := range destChains {
		result = append(result, destChain)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i] < result[j]
	})

	return result
}

func (s *InMemoryOffchainStorage) ListSourceChains(destChainSelector types.ChainSelector) []types.ChainSelector {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sourceChains := make(map[types.ChainSelector]bool)
	for _, entry := range s.storage {
		if entry.CCVData.DestChainSelector == destChainSelector {
			sourceChains[entry.CCVData.SourceChainSelector] = true
		}
	}

	result := make([]types.ChainSelector, 0, len(sourceChains))
	for sourceChain := range sourceChains {
		result = append(result, sourceChain)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i] < result[j]
	})

	return result
}

func (s *InMemoryOffchainStorage) ListVerifierAddresses(destChainSelector, sourceChainSelector types.ChainSelector) [][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	verifierAddresses := make(map[string][]byte)
	for _, entry := range s.storage {
		ccvData := entry.CCVData
		if ccvData.DestChainSelector == destChainSelector && ccvData.SourceChainSelector == sourceChainSelector {
			key := string(ccvData.SourceVerifierAddress)
			verifierAddresses[key] = ccvData.SourceVerifierAddress
		}
	}

	result := make([][]byte, 0, len(verifierAddresses))
	for _, addr := range verifierAddresses {
		result = append(result, addr)
	}

	sort.Slice(result, func(i, j int) bool {
		return string(result[i]) < string(result[j])
	})

	return result
}

// ReaderOnlyView provides a read-only view of the storage that only implements OffchainStorageReader.
type ReaderOnlyView struct {
	storage *InMemoryOffchainStorage
}

func (r *ReaderOnlyView) ReadCCVData(ctx context.Context) ([]types.QueryResponse, error) {
	return r.storage.ReadCCVData(ctx)
}

// Utility methods for testing (not part of the interface).
func (r *ReaderOnlyView) GetTotalCount() int {
	return r.storage.GetTotalCount()
}

// WriterOnlyView provides a write-only view of the storage that only implements OffchainStorageWriter.
type WriterOnlyView struct {
	storage *InMemoryOffchainStorage
}

func (w *WriterOnlyView) WriteCCVData(ctx context.Context, ccvDataList []types.CCVData) error {
	return w.storage.WriteCCVData(ctx, ccvDataList)
}
