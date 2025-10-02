package storage

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ common.IndexerStorage = (*InMemoryStorage)(nil)

var (
	ErrCCVDataNotFound  = fmt.Errorf("CCV data not found")
	ErrDuplicateCCVData = fmt.Errorf("duplicate CCV data")
)

// InMemoryStorage provides efficient in-memory storage optimized for query performance.
type InMemoryStorage struct {
	// Primary storage: messageID -> []CCVData (for O(1) lookup by messageID)
	byMessageID map[string][]protocol.CCVData

	// Timestamp-sorted slice for O(log n) range queries
	byTimestamp []protocol.CCVData

	// Chain selector indexes: selector -> indices into byTimestamp slice
	bySourceChain map[protocol.ChainSelector][]int
	byDestChain   map[protocol.ChainSelector][]int

	// Deduplication index: unique key -> bool (for duplicate detection)
	uniqueKeys map[string]bool

	mu         sync.RWMutex
	monitoring common.IndexerMonitoring
	lggr       logger.Logger
}

func NewInMemoryStorage(lggr logger.Logger, monitoring common.IndexerMonitoring) common.IndexerStorage {
	return &InMemoryStorage{
		byMessageID:   make(map[string][]protocol.CCVData),
		byTimestamp:   make([]protocol.CCVData, 0),
		bySourceChain: make(map[protocol.ChainSelector][]int),
		byDestChain:   make(map[protocol.ChainSelector][]int),
		uniqueKeys:    make(map[string]bool),
		lggr:          lggr,
		monitoring:    monitoring,
	}
}

// GetCCVData performs a O(1) lookup by messageID.
func (i *InMemoryStorage) GetCCVData(ctx context.Context, messageID protocol.Bytes32) ([]protocol.CCVData, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	ccvData, ok := i.byMessageID[messageID.String()]
	if !ok {
		return nil, ErrCCVDataNotFound
	}
	return ccvData, nil
}

// QueryCCVData retrieves all CCVData that matches the filter set.
func (i *InMemoryStorage) QueryCCVData(ctx context.Context, start, end int64, sourceChainSelectors, destChainSelectors []protocol.ChainSelector, limit, offset uint64) (map[string][]protocol.CCVData, error) {
	startQueryMetric := time.Now()
	i.mu.RLock()
	defer i.mu.RUnlock()

	// Get chain selector indices if filters provided
	var chainIndices []int
	if len(sourceChainSelectors) > 0 || len(destChainSelectors) > 0 {
		chainIndices = i.getChainSelectorIndices(sourceChainSelectors, destChainSelectors)
		if len(chainIndices) == 0 {
			return make(map[string][]protocol.CCVData), nil
		}
	}

	// Binary search for timestamp range
	startIdx := i.findTimestampIndex(start, func(ts, target int64) bool { return ts >= target })
	endIdx := i.findTimestampIndex(end, func(ts, target int64) bool { return ts > target })
	if startIdx >= endIdx {
		return make(map[string][]protocol.CCVData), nil
	}

	// Get candidates and apply pagination
	var candidates []protocol.CCVData
	if len(chainIndices) > 0 {
		candidates = i.intersectTimestampAndChainIndices(startIdx, endIdx, chainIndices)
	} else {
		candidates = i.byTimestamp[startIdx:endIdx]
	}

	if offset >= uint64(len(candidates)) {
		return make(map[string][]protocol.CCVData), nil
	}

	startPos, endPos := int(offset), int(offset+limit) // #nosec G115
	if endPos > len(candidates) {
		endPos = len(candidates)
	}

	// Group results by messageID
	results := make(map[string][]protocol.CCVData)
	for _, candidate := range candidates[startPos:endPos] {
		messageID := candidate.MessageID.String()
		results[messageID] = append(results[messageID], candidate)
	}

	i.monitoring.Metrics().RecordStorageQueryDuration(ctx, time.Since(startQueryMetric))
	return results, nil
}

// generateUniqueKey creates a unique key for CCVData based on critical fields.
func (i *InMemoryStorage) generateUniqueKey(ccvData protocol.CCVData) string {
	return fmt.Sprintf("%s:%s:%s",
		ccvData.MessageID.String(),
		ccvData.SourceVerifierAddress.String(),
		ccvData.DestVerifierAddress.String(),
	)
}

// InsertCCVData appends a new CCVData to the storage for the given messageID.
func (i *InMemoryStorage) InsertCCVData(ctx context.Context, ccvData protocol.CCVData) error {
	startInsertMetric := time.Now()
	i.mu.Lock()
	defer i.mu.Unlock()

	// Check for duplicates
	uniqueKey := i.generateUniqueKey(ccvData)
	if i.uniqueKeys[uniqueKey] {
		return ErrDuplicateCCVData
	}

	// Add to messageID index
	messageID := ccvData.MessageID.String()

	// If the MessageID is not in the index, it must be a new message and we should increment the unique messages counter
	if _, ok := i.byMessageID[messageID]; !ok {
		i.monitoring.Metrics().IncrementUniqueMessagesCounter(ctx)
	}

	i.byMessageID[messageID] = append(i.byMessageID[messageID], ccvData)

	// Mark this data as inserted
	i.uniqueKeys[uniqueKey] = true

	// Increment the verification records counter
	i.monitoring.Metrics().IncrementVerificationRecordsCounter(ctx)

	// Insert into timestamp-sorted index
	insertPos := i.findTimestampIndex(ccvData.Timestamp, func(ts, target int64) bool { return ts > target })
	i.byTimestamp = append(i.byTimestamp, protocol.CCVData{})
	copy(i.byTimestamp[insertPos+1:], i.byTimestamp[insertPos:])
	i.byTimestamp[insertPos] = ccvData

	// Update chain selector indexes with index into timestamp slice
	i.addToChainIndex(i.bySourceChain, ccvData.SourceChainSelector, insertPos)
	i.addToChainIndex(i.byDestChain, ccvData.DestChainSelector, insertPos)

	i.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
	return nil
}

// findTimestampIndex finds the first index where timestamp satisfies the condition.
func (i *InMemoryStorage) findTimestampIndex(timestamp int64, condition func(int64, int64) bool) int {
	return sort.Search(len(i.byTimestamp), func(idx int) bool {
		return condition(i.byTimestamp[idx].Timestamp, timestamp)
	})
}

func (i *InMemoryStorage) addToChainIndex(index map[protocol.ChainSelector][]int, selector protocol.ChainSelector, idx int) {
	index[selector] = append(index[selector], idx)
}

// getChainSelectorIndices gets indices for chain selector filters.
func (i *InMemoryStorage) getChainSelectorIndices(sourceChains, destChains []protocol.ChainSelector) []int {
	if len(sourceChains) > 0 && len(destChains) > 0 {
		sourceIndices := i.collectIndices(i.bySourceChain, sourceChains)
		destIndices := i.collectIndices(i.byDestChain, destChains)
		return i.intersectIndices(sourceIndices, destIndices)
	} else if len(sourceChains) > 0 {
		return i.collectIndices(i.bySourceChain, sourceChains)
	} else if len(destChains) > 0 {
		return i.collectIndices(i.byDestChain, destChains)
	}
	return nil
}

// collectIndices collects all indices for the given chain selectors.
func (i *InMemoryStorage) collectIndices(index map[protocol.ChainSelector][]int, selectors []protocol.ChainSelector) []int {
	var result []int
	for _, selector := range selectors {
		if indices, exists := index[selector]; exists {
			result = append(result, indices...)
		}
	}
	return result
}

// intersectIndices finds the intersection of two index slices.
func (i *InMemoryStorage) intersectIndices(slice1, slice2 []int) []int {
	set := make(map[int]bool)
	for _, idx := range slice2 {
		set[idx] = true
	}
	var result []int
	for _, idx := range slice1 {
		if set[idx] {
			result = append(result, idx)
		}
	}
	return result
}

// intersectTimestampAndChainIndices finds data that is both in timestamp range AND chain selector set (optimized).
func (i *InMemoryStorage) intersectTimestampAndChainIndices(startIdx, endIdx int, chainIndices []int) []protocol.CCVData {
	// Pre-allocate with expected capacity
	expectedSize := len(chainIndices)
	if expectedSize > endIdx-startIdx {
		expectedSize = endIdx - startIdx
	}
	candidates := make([]protocol.CCVData, 0, expectedSize)

	// Create a set of valid indices for O(1) lookup
	chainIndexSet := make(map[int]bool, len(chainIndices))
	for _, idx := range chainIndices {
		chainIndexSet[idx] = true
	}

	// Iterate through timestamp range and check membership
	for idx := startIdx; idx < endIdx; idx++ {
		if chainIndexSet[idx] {
			candidates = append(candidates, i.byTimestamp[idx])
		}
	}
	return candidates
}
