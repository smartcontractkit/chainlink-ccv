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
	// Storage
	verifierResultStorage *InMemoryVerifierResultStorage
	messageStorage        *InMemoryMessageStorage

	// Eviction configuration
	ttl         time.Duration // 0 means no TTL-based eviction
	maxSize     int           // 0 means no size-based eviction
	cleanupStop chan struct{}
	cleanupDone chan struct{}
	closeOnce   sync.Once

	mu         sync.RWMutex
	monitoring common.IndexerMonitoring
	lggr       logger.Logger
}

type InMemoryVerifierResultStorage struct {
	// Primary storage: messageID -> []VerifierResultWithMetadata (for O(1) lookup by messageID)
	byMessageID map[string][]common.VerifierResultWithMetadata

	// Timestamp-sorted slice for O(log n) range queries
	byTimestamp []common.VerifierResultWithMetadata

	// Chain selector indexes: selector -> indices into byTimestamp slice
	bySourceChain map[protocol.ChainSelector][]int
	byDestChain   map[protocol.ChainSelector][]int

	// Deduplication index: unique key -> bool (for duplicate detection)
	uniqueKeys map[string]bool
}

type InMemoryMessageStorage struct {
	// Primary storage: messageID -> MessageWithMetadata (for O(1) lookup by messageID)
	byMessageID map[string]common.MessageWithMetadata

	// Timestamp-sorted slice for O(log n) range queries
	byTimestamp []common.MessageWithMetadata

	// Chain selector indexes: selector -> indices into byTimestamp slice
	bySourceChain map[protocol.ChainSelector][]int
	byDestChain   map[protocol.ChainSelector][]int
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
		verifierResultStorage: &InMemoryVerifierResultStorage{
			byMessageID:   make(map[string][]common.VerifierResultWithMetadata),
			byTimestamp:   make([]common.VerifierResultWithMetadata, 0),
			bySourceChain: make(map[protocol.ChainSelector][]int),
			byDestChain:   make(map[protocol.ChainSelector][]int),
			uniqueKeys:    make(map[string]bool),
		},
		messageStorage: &InMemoryMessageStorage{
			byMessageID:   make(map[string]common.MessageWithMetadata),
			byTimestamp:   make([]common.MessageWithMetadata, 0),
			bySourceChain: make(map[protocol.ChainSelector][]int),
			byDestChain:   make(map[protocol.ChainSelector][]int),
		},
		ttl:        config.TTL,
		maxSize:    config.MaxSize,
		lggr:       lggr,
		monitoring: monitoring,
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

// InsertMessage inserts a message into storage.
func (i *InMemoryStorage) InsertMessage(ctx context.Context, message common.MessageWithMetadata) error {
	startInsertMetric := time.Now()
	i.mu.Lock()
	defer i.mu.Unlock()

	messageID := message.Message.MustMessageID().String()

	// Check if message already exists
	if _, exists := i.messageStorage.byMessageID[messageID]; exists {
		// Message already exists, don't overwrite (idempotent behavior)
		return nil
	}

	// Store in messageID index
	i.messageStorage.byMessageID[messageID] = message

	// Insert into timestamp-sorted index
	insertPos := i.findMessageTimestampIndex(message.Metadata.IngestionTimestamp, func(ts, target int64) bool { return ts > target })
	i.messageStorage.byTimestamp = append(i.messageStorage.byTimestamp, common.MessageWithMetadata{})
	copy(i.messageStorage.byTimestamp[insertPos+1:], i.messageStorage.byTimestamp[insertPos:])
	i.messageStorage.byTimestamp[insertPos] = message

	// Update chain selector indexes with index into timestamp slice
	i.addToChainIndex(i.messageStorage.bySourceChain, message.Message.SourceChainSelector, insertPos)
	i.addToChainIndex(i.messageStorage.byDestChain, message.Message.DestChainSelector, insertPos)

	i.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
	return nil
}

// BatchInsertMessages inserts multiple messages efficiently.
func (i *InMemoryStorage) BatchInsertMessages(ctx context.Context, messages []common.MessageWithMetadata) error {
	if len(messages) == 0 {
		return nil
	}

	startInsertMetric := time.Now()
	i.mu.Lock()
	defer i.mu.Unlock()

	insertedCount := 0

	for _, message := range messages {
		messageID := message.Message.MustMessageID().String()

		// Check if message already exists
		if _, exists := i.messageStorage.byMessageID[messageID]; exists {
			continue // Skip duplicates
		}

		// Store in messageID index
		i.messageStorage.byMessageID[messageID] = message

		// Insert into timestamp-sorted index
		insertPos := i.findMessageTimestampIndex(message.Metadata.IngestionTimestamp, func(ts, target int64) bool { return ts > target })
		i.messageStorage.byTimestamp = append(i.messageStorage.byTimestamp, common.MessageWithMetadata{})
		copy(i.messageStorage.byTimestamp[insertPos+1:], i.messageStorage.byTimestamp[insertPos:])
		i.messageStorage.byTimestamp[insertPos] = message

		// Update chain selector indexes with index into timestamp slice
		i.addToChainIndex(i.messageStorage.bySourceChain, message.Message.SourceChainSelector, insertPos)
		i.addToChainIndex(i.messageStorage.byDestChain, message.Message.DestChainSelector, insertPos)

		insertedCount++
	}

	i.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
	return nil
}

// GetMessage performs a O(1) lookup by messageID.
func (i *InMemoryStorage) GetMessage(ctx context.Context, messageID protocol.Bytes32) (common.MessageWithMetadata, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	message, ok := i.messageStorage.byMessageID[messageID.String()]
	if !ok {
		return common.MessageWithMetadata{}, ErrMessageNotFound
	}
	return message, nil
}

// QueryMessages retrieves all messages that match the filter set.
func (i *InMemoryStorage) QueryMessages(ctx context.Context, start, end int64, sourceChainSelectors, destChainSelectors []protocol.ChainSelector, limit, offset uint64) ([]common.MessageWithMetadata, error) {
	startQueryMetric := time.Now()
	i.mu.RLock()
	defer i.mu.RUnlock()

	// Get chain selector indices if filters provided
	var chainIndices []int
	if len(sourceChainSelectors) > 0 || len(destChainSelectors) > 0 {
		chainIndices = i.getMessageChainSelectorIndices(sourceChainSelectors, destChainSelectors)
		if len(chainIndices) == 0 {
			return []common.MessageWithMetadata{}, nil
		}
	}

	// Binary search for timestamp range
	startIdx := i.findMessageTimestampIndex(time.UnixMilli(start), func(ts, target int64) bool { return ts >= target })
	endIdx := i.findMessageTimestampIndex(time.UnixMilli(end), func(ts, target int64) bool { return ts > target })
	if startIdx >= endIdx {
		return []common.MessageWithMetadata{}, nil
	}

	// Get candidates and apply pagination
	var candidates []common.MessageWithMetadata
	if len(chainIndices) > 0 {
		candidates = i.intersectMessageTimestampAndChainIndices(startIdx, endIdx, chainIndices)
	} else {
		candidates = i.messageStorage.byTimestamp[startIdx:endIdx]
	}

	if offset >= uint64(len(candidates)) {
		return []common.MessageWithMetadata{}, nil
	}

	startPos, endPos := int(offset), int(offset+limit) // #nosec G115
	if endPos > len(candidates) {
		endPos = len(candidates)
	}

	i.monitoring.Metrics().RecordStorageQueryDuration(ctx, time.Since(startQueryMetric))
	return candidates[startPos:endPos], nil
}

// UpdateMessageStatus updates the status of a message in storage.
func (i *InMemoryStorage) UpdateMessageStatus(ctx context.Context, messageID protocol.Bytes32, status common.MessageStatus, lastErr string) error {
	startUpdateMetric := time.Now()
	i.mu.Lock()
	defer i.mu.Unlock()

	messageIDStr := messageID.String()
	message, exists := i.messageStorage.byMessageID[messageIDStr]
	if !exists {
		return fmt.Errorf("message not found: %s", messageIDStr)
	}

	// Update the status and lastErr
	message.Metadata.Status = status
	message.Metadata.LastErr = lastErr

	// Update in the byMessageID index
	i.messageStorage.byMessageID[messageIDStr] = message

	// Update in the timestamp-sorted slice
	// Find the message in the slice and update it
	for idx := range i.messageStorage.byTimestamp {
		if i.messageStorage.byTimestamp[idx].Message.MustMessageID().String() == messageIDStr {
			i.messageStorage.byTimestamp[idx] = message
			break
		}
	}

	i.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startUpdateMetric))
	return nil
}

// findMessageTimestampIndex finds the first index where timestamp satisfies the condition for messages.
func (i *InMemoryStorage) findMessageTimestampIndex(timestamp time.Time, condition func(int64, int64) bool) int {
	return sort.Search(len(i.messageStorage.byTimestamp), func(idx int) bool {
		return condition(i.messageStorage.byTimestamp[idx].Metadata.IngestionTimestamp.UnixMilli(), timestamp.UnixMilli())
	})
}

// GetCCVData performs a O(1) lookup by messageID.
func (i *InMemoryStorage) GetCCVData(ctx context.Context, messageID protocol.Bytes32) ([]common.VerifierResultWithMetadata, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	ccvData, ok := i.verifierResultStorage.byMessageID[messageID.String()]
	if !ok {
		return nil, ErrCCVDataNotFound
	}
	return ccvData, nil
}

// QueryCCVData retrieves all CCVData that matches the filter set.
func (i *InMemoryStorage) QueryCCVData(ctx context.Context, start, end int64, sourceChainSelectors, destChainSelectors []protocol.ChainSelector, limit, offset uint64) (map[string][]common.VerifierResultWithMetadata, error) {
	startQueryMetric := time.Now()
	i.mu.RLock()
	defer i.mu.RUnlock()

	// Get chain selector indices if filters provided
	var chainIndices []int
	if len(sourceChainSelectors) > 0 || len(destChainSelectors) > 0 {
		chainIndices = i.getChainSelectorIndices(sourceChainSelectors, destChainSelectors)
		if len(chainIndices) == 0 {
			return make(map[string][]common.VerifierResultWithMetadata), nil
		}
	}

	// Binary search for timestamp range
	startIdx := i.findTimestampIndex(time.UnixMilli(start), func(ts, target int64) bool { return ts >= target })
	endIdx := i.findTimestampIndex(time.UnixMilli(end), func(ts, target int64) bool { return ts > target })
	if startIdx >= endIdx {
		return make(map[string][]common.VerifierResultWithMetadata), nil
	}

	// Get candidates and apply pagination
	var candidates []common.VerifierResultWithMetadata
	if len(chainIndices) > 0 {
		candidates = i.intersectTimestampAndChainIndices(startIdx, endIdx, chainIndices)
	} else {
		candidates = i.verifierResultStorage.byTimestamp[startIdx:endIdx]
	}

	if offset >= uint64(len(candidates)) {
		return make(map[string][]common.VerifierResultWithMetadata), nil
	}

	startPos, endPos := int(offset), int(offset+limit) // #nosec G115
	if endPos > len(candidates) {
		endPos = len(candidates)
	}

	// Group results by messageID
	results := make(map[string][]common.VerifierResultWithMetadata)
	for _, candidate := range candidates[startPos:endPos] {
		messageID := candidate.VerifierResult.MessageID.String()
		results[messageID] = append(results[messageID], candidate)
	}

	i.monitoring.Metrics().RecordStorageQueryDuration(ctx, time.Since(startQueryMetric))
	if len(results) == 0 {
		return nil, ErrCCVDataNotFound
	}

	return results, nil
}

// generateUniqueKey creates a unique key for CCVData based on critical fields.
func (i *InMemoryStorage) generateUniqueKey(ccvData common.VerifierResultWithMetadata) string {
	return fmt.Sprintf("%s:%s:%s",
		ccvData.VerifierResult.MessageID.String(),
		ccvData.VerifierResult.VerifierSourceAddress.String(),
		ccvData.VerifierResult.VerifierDestAddress.String(),
	)
}

// InsertCCVData appends a new CCVData to the storage for the given messageID.
func (i *InMemoryStorage) InsertCCVData(ctx context.Context, ccvData common.VerifierResultWithMetadata) error {
	startInsertMetric := time.Now()
	i.mu.Lock()
	defer i.mu.Unlock()

	// Check for duplicates
	uniqueKey := i.generateUniqueKey(ccvData)
	if i.verifierResultStorage.uniqueKeys[uniqueKey] {
		return ErrDuplicateCCVData
	}

	// Add to messageID index
	messageID := ccvData.VerifierResult.MessageID.String()

	// If the MessageID is not in the index, it must be a new message and we should increment the unique messages counter
	if _, ok := i.verifierResultStorage.byMessageID[messageID]; !ok {
		i.monitoring.Metrics().IncrementUniqueMessagesCounter(ctx)
	}

	i.verifierResultStorage.byMessageID[messageID] = append(i.verifierResultStorage.byMessageID[messageID], ccvData)

	// Mark this data as inserted
	i.verifierResultStorage.uniqueKeys[uniqueKey] = true

	// Increment the verification records counter
	i.monitoring.Metrics().IncrementVerificationRecordsCounter(ctx)

	// Insert into timestamp-sorted index
	insertPos := i.findTimestampIndex(ccvData.Metadata.IngestionTimestamp, func(ts, target int64) bool { return ts > target })
	i.verifierResultStorage.byTimestamp = append(i.verifierResultStorage.byTimestamp, common.VerifierResultWithMetadata{})
	copy(i.verifierResultStorage.byTimestamp[insertPos+1:], i.verifierResultStorage.byTimestamp[insertPos:])
	i.verifierResultStorage.byTimestamp[insertPos] = ccvData

	// Update chain selector indexes with index into timestamp slice
	i.addToChainIndex(i.verifierResultStorage.bySourceChain, ccvData.VerifierResult.Message.SourceChainSelector, insertPos)
	i.addToChainIndex(i.verifierResultStorage.byDestChain, ccvData.VerifierResult.Message.DestChainSelector, insertPos)

	i.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
	return nil
}

// BatchInsertCCVData inserts multiple CCVData entries efficiently.
func (i *InMemoryStorage) BatchInsertCCVData(ctx context.Context, ccvDataList []common.VerifierResultWithMetadata) error {
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
		if i.verifierResultStorage.uniqueKeys[uniqueKey] {
			continue // Skip duplicates
		}

		// Add to messageID index
		messageID := ccvData.VerifierResult.MessageID.String()

		// If the MessageID is not in the index, it must be a new message
		if _, ok := i.verifierResultStorage.byMessageID[messageID]; !ok {
			newUniqueMessages++
		}

		i.verifierResultStorage.byMessageID[messageID] = append(i.verifierResultStorage.byMessageID[messageID], ccvData)

		// Mark this data as inserted
		i.verifierResultStorage.uniqueKeys[uniqueKey] = true
		insertedCount++

		// Insert into timestamp-sorted index
		insertPos := i.findTimestampIndex(ccvData.Metadata.IngestionTimestamp, func(ts, target int64) bool { return ts > target })
		i.verifierResultStorage.byTimestamp = append(i.verifierResultStorage.byTimestamp, common.VerifierResultWithMetadata{})
		copy(i.verifierResultStorage.byTimestamp[insertPos+1:], i.verifierResultStorage.byTimestamp[insertPos:])
		i.verifierResultStorage.byTimestamp[insertPos] = ccvData

		// Update chain selector indexes with index into timestamp slice
		i.addToChainIndex(i.verifierResultStorage.bySourceChain, ccvData.VerifierResult.Message.SourceChainSelector, insertPos)
		i.addToChainIndex(i.verifierResultStorage.byDestChain, ccvData.VerifierResult.Message.DestChainSelector, insertPos)
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
	return sort.Search(len(i.verifierResultStorage.byTimestamp), func(idx int) bool {
		return condition(i.verifierResultStorage.byTimestamp[idx].Metadata.IngestionTimestamp.UnixMilli(), timestamp.UnixMilli())
	})
}

func (i *InMemoryStorage) addToChainIndex(index map[protocol.ChainSelector][]int, selector protocol.ChainSelector, idx int) {
	index[selector] = append(index[selector], idx)
}

// getChainSelectorIndices gets indices for chain selector filters.
func (i *InMemoryStorage) getChainSelectorIndices(sourceChains, destChains []protocol.ChainSelector) []int {
	if len(sourceChains) > 0 && len(destChains) > 0 {
		sourceIndices := i.collectIndices(i.verifierResultStorage.bySourceChain, sourceChains)
		destIndices := i.collectIndices(i.verifierResultStorage.byDestChain, destChains)
		return i.intersectIndices(sourceIndices, destIndices)
	} else if len(sourceChains) > 0 {
		return i.collectIndices(i.verifierResultStorage.bySourceChain, sourceChains)
	} else if len(destChains) > 0 {
		return i.collectIndices(i.verifierResultStorage.byDestChain, destChains)
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
func (i *InMemoryStorage) intersectTimestampAndChainIndices(startIdx, endIdx int, chainIndices []int) []common.VerifierResultWithMetadata {
	// Pre-allocate with expected capacity
	expectedSize := len(chainIndices)
	if expectedSize > endIdx-startIdx {
		expectedSize = endIdx - startIdx
	}
	candidates := make([]common.VerifierResultWithMetadata, 0, expectedSize)

	// Create a set of valid indices for O(1) lookup
	chainIndexSet := make(map[int]bool, len(chainIndices))
	for _, idx := range chainIndices {
		chainIndexSet[idx] = true
	}

	// Iterate through timestamp range and check membership
	for idx := startIdx; idx < endIdx; idx++ {
		if chainIndexSet[idx] {
			candidates = append(candidates, i.verifierResultStorage.byTimestamp[idx])
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

	beforeCount := len(i.verifierResultStorage.byTimestamp)
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
		for _, data := range i.verifierResultStorage.byTimestamp {
			if data.Metadata.IngestionTimestamp.UnixMilli() >= cutoffTime {
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
		"afterCount", len(i.verifierResultStorage.byTimestamp),
	)
}

// evictOldestItems removes the first n items from storage.
// Must be called with lock held.
func (i *InMemoryStorage) evictOldestItems(n int) {
	if n <= 0 || n > len(i.verifierResultStorage.byTimestamp) {
		return
	}

	// Items to remove are at the front of the byTimestamp slice
	itemsToRemove := i.verifierResultStorage.byTimestamp[:n]

	// Track which messageIDs need to be cleaned up
	messageIDCounts := make(map[string]int)
	for _, data := range i.verifierResultStorage.byMessageID {
		messageIDCounts[data[0].VerifierResult.MessageID.String()] = len(data)
	}

	// Remove from indexes
	for _, data := range itemsToRemove {
		messageID := data.VerifierResult.MessageID.String()

		// Remove from uniqueKeys
		uniqueKey := i.generateUniqueKey(data)
		delete(i.verifierResultStorage.uniqueKeys, uniqueKey)

		// Remove from byMessageID
		if existing, ok := i.verifierResultStorage.byMessageID[messageID]; ok {
			// Find and remove this specific entry
			newList := make([]common.VerifierResultWithMetadata, 0, len(existing)-1)
			for _, item := range existing {
				if i.generateUniqueKey(item) != uniqueKey {
					newList = append(newList, item)
				}
			}

			if len(newList) == 0 {
				delete(i.verifierResultStorage.byMessageID, messageID)
			} else {
				i.verifierResultStorage.byMessageID[messageID] = newList
			}
		}
	}

	// Remove from byTimestamp (just slice it)
	i.verifierResultStorage.byTimestamp = i.verifierResultStorage.byTimestamp[n:]

	// Rebuild chain selector indexes since indices have changed
	i.rebuildChainIndexes()
}

// rebuildChainIndexes rebuilds the chain selector indexes after items are removed.
// Must be called with lock held.
func (i *InMemoryStorage) rebuildChainIndexes() {
	i.verifierResultStorage.bySourceChain = make(map[protocol.ChainSelector][]int)
	i.verifierResultStorage.byDestChain = make(map[protocol.ChainSelector][]int)

	for idx, data := range i.verifierResultStorage.byTimestamp {
		i.verifierResultStorage.bySourceChain[data.VerifierResult.Message.SourceChainSelector] = append(i.verifierResultStorage.bySourceChain[data.VerifierResult.Message.SourceChainSelector], idx)
		i.verifierResultStorage.byDestChain[data.VerifierResult.Message.DestChainSelector] = append(i.verifierResultStorage.byDestChain[data.VerifierResult.Message.DestChainSelector], idx)
	}
}

// getMessageChainSelectorIndices gets indices for chain selector filters for messages.
func (i *InMemoryStorage) getMessageChainSelectorIndices(sourceChains, destChains []protocol.ChainSelector) []int {
	if len(sourceChains) > 0 && len(destChains) > 0 {
		sourceIndices := i.collectMessageIndices(i.messageStorage.bySourceChain, sourceChains)
		destIndices := i.collectMessageIndices(i.messageStorage.byDestChain, destChains)
		return i.intersectIndices(sourceIndices, destIndices)
	} else if len(sourceChains) > 0 {
		return i.collectMessageIndices(i.messageStorage.bySourceChain, sourceChains)
	} else if len(destChains) > 0 {
		return i.collectMessageIndices(i.messageStorage.byDestChain, destChains)
	}
	return nil
}

// collectMessageIndices collects all indices for the given chain selectors for messages.
func (i *InMemoryStorage) collectMessageIndices(index map[protocol.ChainSelector][]int, selectors []protocol.ChainSelector) []int {
	var result []int
	for _, selector := range selectors {
		if indices, exists := index[selector]; exists {
			result = append(result, indices...)
		}
	}
	return result
}

// intersectMessageTimestampAndChainIndices finds messages that are both in timestamp range AND chain selector set.
func (i *InMemoryStorage) intersectMessageTimestampAndChainIndices(startIdx, endIdx int, chainIndices []int) []common.MessageWithMetadata {
	expectedSize := len(chainIndices)
	if expectedSize > endIdx-startIdx {
		expectedSize = endIdx - startIdx
	}
	candidates := make([]common.MessageWithMetadata, 0, expectedSize)

	chainIndexSet := make(map[int]bool, len(chainIndices))
	for _, idx := range chainIndices {
		chainIndexSet[idx] = true
	}

	for idx := startIdx; idx < endIdx; idx++ {
		if chainIndexSet[idx] {
			candidates = append(candidates, i.messageStorage.byTimestamp[idx])
		}
	}
	return candidates
}

// Close stops the background cleanup goroutine and releases resources.
func (i *InMemoryStorage) Close() error {
	if i.cleanupStop == nil {
		return nil
	}

	var closed bool
	i.closeOnce.Do(func() {
		close(i.cleanupStop)
		// Wait for cleanup goroutine to finish with a timeout to prevent hanging
		select {
		case <-i.cleanupDone:
			closed = true
		case <-time.After(5 * time.Second):
			i.lggr.Warn("Timeout waiting for cleanup goroutine to finish")
		}
		i.lggr.Info("In-memory storage closed")
	})

	if !closed {
		return nil
	}
	return nil
}
