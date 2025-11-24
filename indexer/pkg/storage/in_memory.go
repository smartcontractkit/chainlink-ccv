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

// InMemoryStorage provides efficient in-memory storage optimized for query performance.
type InMemoryStorage struct {
	// Primary storage: messageID -> []CCVData (for O(1) lookup by messageID)
	byMessageID map[string][]protocol.VerifierResult

	// Timestamp-sorted slice for O(log n) range queries
	byTimestamp []protocol.VerifierResult

	// Chain selector indexes: selector -> indices into byTimestamp slice
	bySourceChain map[protocol.ChainSelector][]int
	byDestChain   map[protocol.ChainSelector][]int

	// Deduplication index: unique key -> bool (for duplicate detection)
	uniqueKeys map[string]bool

	// Eviction configuration
	ttl         time.Duration // 0 means no TTL-based eviction
	maxSize     int           // 0 means no size-based eviction
	cleanupStop chan struct{}
	cleanupDone chan struct{}

	mu         sync.RWMutex
	monitoring common.IndexerMonitoring
	lggr       logger.Logger
}

// InMemoryStorageConfig holds configuration for InMemoryStorage.
type InMemoryStorageConfig struct {
	// TTL is the time-to-live for items. Items older than this will be evicted.
	// Set to 0 to disable TTL-based eviction.
	TTL time.Duration
	// MaxSize is the maximum number of items to keep in storage.
	// When exceeded, oldest items will be evicted.
	// Set to 0 to disable size-based eviction.
	MaxSize int
	// CleanupInterval is how often to run the background cleanup goroutine.
	// Defaults to 1 minute if not set and TTL is enabled.
	CleanupInterval time.Duration
}

func NewInMemoryStorage(lggr logger.Logger, monitoring common.IndexerMonitoring) common.IndexerStorage {
	return NewInMemoryStorageWithConfig(lggr, monitoring, InMemoryStorageConfig{})
}

func NewInMemoryStorageWithConfig(lggr logger.Logger, monitoring common.IndexerMonitoring, config InMemoryStorageConfig) common.IndexerStorage {
	storage := &InMemoryStorage{
		byMessageID:   make(map[string][]protocol.VerifierResult),
		byTimestamp:   make([]protocol.VerifierResult, 0),
		bySourceChain: make(map[protocol.ChainSelector][]int),
		byDestChain:   make(map[protocol.ChainSelector][]int),
		uniqueKeys:    make(map[string]bool),
		ttl:           config.TTL,
		maxSize:       config.MaxSize,
		lggr:          lggr,
		monitoring:    monitoring,
	}

	// Start background cleanup goroutine if TTL or MaxSize is enabled
	if config.TTL > 0 || config.MaxSize > 0 {
		cleanupInterval := config.CleanupInterval
		if cleanupInterval == 0 {
			if config.TTL > 0 {
				cleanupInterval = 1 * time.Minute
			} else {
				// For size-only eviction, check less frequently
				cleanupInterval = 5 * time.Minute
			}
		}

		storage.cleanupStop = make(chan struct{})
		storage.cleanupDone = make(chan struct{})

		go storage.backgroundCleanup(cleanupInterval)

		lggr.Infow("Started in-memory storage with eviction",
			"ttl", config.TTL,
			"maxSize", config.MaxSize,
			"cleanupInterval", cleanupInterval,
		)
	}

	return storage
}

// GetCCVData performs a O(1) lookup by messageID.
func (i *InMemoryStorage) GetCCVData(ctx context.Context, messageID protocol.Bytes32) ([]protocol.VerifierResult, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	ccvData, ok := i.byMessageID[messageID.String()]
	if !ok {
		return nil, ErrCCVDataNotFound
	}
	return ccvData, nil
}

// QueryCCVData retrieves all CCVData that matches the filter set.
func (i *InMemoryStorage) QueryCCVData(ctx context.Context, start, end int64, sourceChainSelectors, destChainSelectors []protocol.ChainSelector, limit, offset uint64) (map[string][]protocol.VerifierResult, error) {
	startQueryMetric := time.Now()
	i.mu.RLock()
	defer i.mu.RUnlock()

	// Get chain selector indices if filters provided
	var chainIndices []int
	if len(sourceChainSelectors) > 0 || len(destChainSelectors) > 0 {
		chainIndices = i.getChainSelectorIndices(sourceChainSelectors, destChainSelectors)
		if len(chainIndices) == 0 {
			return make(map[string][]protocol.VerifierResult), nil
		}
	}

	// Binary search for timestamp range
	startIdx := i.findTimestampIndex(time.UnixMilli(start), func(ts, target int64) bool { return ts >= target })
	endIdx := i.findTimestampIndex(time.UnixMilli(end), func(ts, target int64) bool { return ts > target })
	if startIdx >= endIdx {
		return make(map[string][]protocol.VerifierResult), nil
	}

	// Get candidates and apply pagination
	var candidates []protocol.VerifierResult
	if len(chainIndices) > 0 {
		candidates = i.intersectTimestampAndChainIndices(startIdx, endIdx, chainIndices)
	} else {
		candidates = i.byTimestamp[startIdx:endIdx]
	}

	if offset >= uint64(len(candidates)) {
		return make(map[string][]protocol.VerifierResult), nil
	}

	startPos, endPos := int(offset), int(offset+limit) // #nosec G115
	if endPos > len(candidates) {
		endPos = len(candidates)
	}

	// Group results by messageID
	results := make(map[string][]protocol.VerifierResult)
	for _, candidate := range candidates[startPos:endPos] {
		messageID := candidate.MessageID.String()
		results[messageID] = append(results[messageID], candidate)
	}

	i.monitoring.Metrics().RecordStorageQueryDuration(ctx, time.Since(startQueryMetric))
	if len(results) == 0 {
		return nil, ErrCCVDataNotFound
	}

	return results, nil
}

// generateUniqueKey creates a unique key for CCVData based on critical fields.
func (i *InMemoryStorage) generateUniqueKey(ccvData protocol.VerifierResult) string {
	return fmt.Sprintf("%s:%s:%s",
		ccvData.MessageID.String(),
		ccvData.VerifierSourceAddress.String(),
		ccvData.VerifierDestAddress.String(),
	)
}

// InsertCCVData appends a new CCVData to the storage for the given messageID.
func (i *InMemoryStorage) InsertCCVData(ctx context.Context, ccvData protocol.VerifierResult) error {
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
	i.byTimestamp = append(i.byTimestamp, protocol.VerifierResult{})
	copy(i.byTimestamp[insertPos+1:], i.byTimestamp[insertPos:])
	i.byTimestamp[insertPos] = ccvData

	// Update chain selector indexes with index into timestamp slice
	i.addToChainIndex(i.bySourceChain, ccvData.Message.SourceChainSelector, insertPos)
	i.addToChainIndex(i.byDestChain, ccvData.Message.DestChainSelector, insertPos)

	i.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
	return nil
}

// BatchInsertCCVData inserts multiple CCVData entries efficiently.
func (i *InMemoryStorage) BatchInsertCCVData(ctx context.Context, ccvDataList []protocol.VerifierResult) error {
	if len(ccvDataList) == 0 {
		return nil
	}

	startInsertMetric := time.Now()
	i.mu.Lock()
	defer i.mu.Unlock()

	// Track unique messages we've seen before this batch
	newUniqueMessages := 0
	insertedCount := 0

	for _, ccvData := range ccvDataList {
		// Check for duplicates
		uniqueKey := i.generateUniqueKey(ccvData)
		if i.uniqueKeys[uniqueKey] {
			continue // Skip duplicates
		}

		// Add to messageID index
		messageID := ccvData.MessageID.String()

		// If the MessageID is not in the index, it must be a new message
		if _, ok := i.byMessageID[messageID]; !ok {
			newUniqueMessages++
		}

		i.byMessageID[messageID] = append(i.byMessageID[messageID], ccvData)

		// Mark this data as inserted
		i.uniqueKeys[uniqueKey] = true
		insertedCount++

		// Insert into timestamp-sorted index
		insertPos := i.findTimestampIndex(ccvData.Timestamp, func(ts, target int64) bool { return ts > target })
		i.byTimestamp = append(i.byTimestamp, protocol.VerifierResult{})
		copy(i.byTimestamp[insertPos+1:], i.byTimestamp[insertPos:])
		i.byTimestamp[insertPos] = ccvData

		// Update chain selector indexes with index into timestamp slice
		i.addToChainIndex(i.bySourceChain, ccvData.Message.SourceChainSelector, insertPos)
		i.addToChainIndex(i.byDestChain, ccvData.Message.DestChainSelector, insertPos)
	}

	// Update metrics
	for j := 0; j < newUniqueMessages; j++ {
		i.monitoring.Metrics().IncrementUniqueMessagesCounter(ctx)
	}
	for j := 0; j < insertedCount; j++ {
		i.monitoring.Metrics().IncrementVerificationRecordsCounter(ctx)
	}

	i.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
	return nil
}

// findTimestampIndex finds the first index where timestamp satisfies the condition.
func (i *InMemoryStorage) findTimestampIndex(timestamp time.Time, condition func(int64, int64) bool) int {
	return sort.Search(len(i.byTimestamp), func(idx int) bool {
		return condition(i.byTimestamp[idx].Timestamp.UnixMilli(), timestamp.UnixMilli())
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
func (i *InMemoryStorage) intersectTimestampAndChainIndices(startIdx, endIdx int, chainIndices []int) []protocol.VerifierResult {
	// Pre-allocate with expected capacity
	expectedSize := len(chainIndices)
	if expectedSize > endIdx-startIdx {
		expectedSize = endIdx - startIdx
	}
	candidates := make([]protocol.VerifierResult, 0, expectedSize)

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

// backgroundCleanup runs periodic cleanup to remove expired items.
func (i *InMemoryStorage) backgroundCleanup(interval time.Duration) {
	defer close(i.cleanupDone)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			i.cleanup()
		case <-i.cleanupStop:
			i.lggr.Info("Stopping background cleanup goroutine")
			return
		}
	}
}

// cleanup removes items that have exceeded their TTL or exceed the max size.
func (i *InMemoryStorage) cleanup() {
	i.mu.Lock()
	defer i.mu.Unlock()

	beforeCount := len(i.byTimestamp)
	if beforeCount == 0 {
		return
	}

	// Calculate how many items to remove
	itemsToRemove := 0

	// 1. Check for TTL-based eviction
	if i.ttl > 0 {
		cutoffTime := time.Now().Add(-i.ttl).UnixMilli()
		// Find the first index where timestamp is >= cutoffTime
		expiredCount := 0
		for _, data := range i.byTimestamp {
			if data.Timestamp.UnixMilli() >= cutoffTime {
				break // Since byTimestamp is sorted, we can stop here
			}
			expiredCount++
		}
		itemsToRemove = expiredCount
	}

	// 2. Check for size-based eviction
	if i.maxSize > 0 {
		remainingAfterTTL := beforeCount - itemsToRemove
		if remainingAfterTTL > i.maxSize {
			// Need to remove additional items beyond TTL expiration
			additionalToRemove := remainingAfterTTL - i.maxSize
			itemsToRemove += additionalToRemove
		}
	}

	if itemsToRemove == 0 {
		return
	}

	// Don't remove more than we have
	if itemsToRemove > beforeCount {
		itemsToRemove = beforeCount
	}

	// Remove items from the front of byTimestamp (oldest items)
	i.evictOldestItems(itemsToRemove)

	i.lggr.Infow("Cleaned up expired/excess items",
		"removedCount", itemsToRemove,
		"beforeCount", beforeCount,
		"afterCount", len(i.byTimestamp),
	)
}

// evictOldestItems removes the first n items from storage.
// Must be called with lock held.
func (i *InMemoryStorage) evictOldestItems(n int) {
	if n <= 0 || n > len(i.byTimestamp) {
		return
	}

	// Items to remove are at the front of the byTimestamp slice
	itemsToRemove := i.byTimestamp[:n]

	// Track which messageIDs need to be cleaned up
	messageIDCounts := make(map[string]int)
	for _, data := range i.byMessageID {
		messageIDCounts[data[0].MessageID.String()] = len(data)
	}

	// Remove from indexes
	for _, data := range itemsToRemove {
		messageID := data.MessageID.String()

		// Remove from uniqueKeys
		uniqueKey := i.generateUniqueKey(data)
		delete(i.uniqueKeys, uniqueKey)

		// Remove from byMessageID
		if existing, ok := i.byMessageID[messageID]; ok {
			// Find and remove this specific entry
			newList := make([]protocol.VerifierResult, 0, len(existing)-1)
			for _, item := range existing {
				if i.generateUniqueKey(item) != uniqueKey {
					newList = append(newList, item)
				}
			}

			if len(newList) == 0 {
				delete(i.byMessageID, messageID)
			} else {
				i.byMessageID[messageID] = newList
			}
		}
	}

	// Remove from byTimestamp (just slice it)
	i.byTimestamp = i.byTimestamp[n:]

	// Rebuild chain selector indexes since indices have changed
	i.rebuildChainIndexes()
}

// rebuildChainIndexes rebuilds the chain selector indexes after items are removed.
// Must be called with lock held.
func (i *InMemoryStorage) rebuildChainIndexes() {
	i.bySourceChain = make(map[protocol.ChainSelector][]int)
	i.byDestChain = make(map[protocol.ChainSelector][]int)

	for idx, data := range i.byTimestamp {
		i.bySourceChain[data.Message.SourceChainSelector] = append(i.bySourceChain[data.Message.SourceChainSelector], idx)
		i.byDestChain[data.Message.DestChainSelector] = append(i.byDestChain[data.Message.DestChainSelector], idx)
	}
}

// Close stops the background cleanup goroutine and releases resources.
func (i *InMemoryStorage) Close() error {
	if i.cleanupStop != nil {
		close(i.cleanupStop)
		<-i.cleanupDone
		i.lggr.Info("In-memory storage closed")
	}
	return nil
}
