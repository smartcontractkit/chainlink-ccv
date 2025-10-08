// file: ddb/day_merge_iterator.go
package query

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Factory to build a shard iterator for (day, shard), optionally seeded with a per-shard token.
type ShardIteratorFactory func(day, shard string, prev *SinglePartitionPaginationToken) ItemIterator

type DynamoAggregatedReportFeedIterator struct {
	dayIter              *DayIterator
	shards               []string
	shardIteratorFactory ShardIteratorFactory

	merged      *MergeIterator
	currentItem map[string]types.AttributeValue
	err         error

	inputToken    *AggregatedReportPaginationToken
	accumCursors  map[string]SinglePartitionPaginationToken // per-shard state for the CURRENT day
	mergedHasMore bool
	currentDay    string
}

func NewDynamoAggregatedReportFeedIterator(
	start, end int64,
	minDate time.Time,
	inputToken *AggregatedReportPaginationToken, // may be nil
	shards []string,
	shardIteratorFactory ShardIteratorFactory,
) *DynamoAggregatedReportFeedIterator {
	return &DynamoAggregatedReportFeedIterator{
		dayIter:              NewDayIterator(start, end, minDate, inputToken),
		shards:               shards,
		shardIteratorFactory: shardIteratorFactory,
		inputToken:           inputToken,
		accumCursors:         make(map[string]SinglePartitionPaginationToken),
	}
}

func (d *DynamoAggregatedReportFeedIterator) Item() map[string]types.AttributeValue {
	return d.currentItem
}
func (d *DynamoAggregatedReportFeedIterator) Err() error { return d.err }

// Next emits the globally-oldest item across shards/days, with stable tiebreak.
func (d *DynamoAggregatedReportFeedIterator) Next(ctx context.Context) bool {
	if d.err != nil {
		return false
	}

	for {
		// Try to get next item from current day's merge iterator
		if hasNextRecord := d.tryGetNextRecordFromCurrentDay(ctx); hasNextRecord {
			return true
		}

		// Current day exhausted, try to advance to next day
		if hasMoreDay := d.advanceToNextValidDay(); !hasMoreDay {
			return false // No more days
		}

		// Set up merge iterator for new day
		if hasRecordsInCurrentDay := d.setupMergeIteratorForCurrentDay(); !hasRecordsInCurrentDay {
			// No data in this day, continue to next day
			d.dayIter.Advance()
			continue
		}
	}
}

// tryGetNextRecordFromCurrentDay attempts to get the next item from the current day's merge iterator.
func (d *DynamoAggregatedReportFeedIterator) tryGetNextRecordFromCurrentDay(ctx context.Context) bool {
	if d.merged == nil {
		return false
	}

	if d.merged.Next(ctx) {
		d.currentItem = d.merged.Item()
		d.updateCursors()
		return true
	}

	// Check for errors in the merge iterator
	if err := d.merged.Err(); err != nil {
		d.err = fmt.Errorf("merge iter: %w", err)
		return false
	}

	// Cleanly done with this day: prepare for next day
	d.merged = nil
	d.dayIter.Advance()
	return false
}

// advanceToNextValidDay moves to the next day that needs processing.
func (d *DynamoAggregatedReportFeedIterator) advanceToNextValidDay() bool {
	if !d.dayIter.Next() {
		return false // No more days
	}

	d.currentDay = d.dayIter.Day()
	d.resetShardTokensIfDayChanged()
	d.initializeShardTokensFromPaginationToken()
	return true
}

// resetShardTokensIfDayChanged resets per-shard tokens when switching to a different GSI PK.
func (d *DynamoAggregatedReportFeedIterator) resetShardTokensIfDayChanged() {
	if d.inputToken != nil && d.inputToken.LastDay != "" && d.currentDay != d.inputToken.LastDay {
		d.inputToken.Tokens = make(map[string]SinglePartitionPaginationToken)
	}
}

// initializeShardTokensFromPaginationToken initializes cursors from incoming token to avoid rewinding quiet shards.
func (d *DynamoAggregatedReportFeedIterator) initializeShardTokensFromPaginationToken() {
	d.accumCursors = make(map[string]SinglePartitionPaginationToken)
	if d.inputToken != nil && d.inputToken.Tokens != nil {
		for k, v := range d.inputToken.Tokens {
			d.accumCursors[k] = v
		}
	}
}

// setupMergeIteratorForCurrentDay builds shard iterators and creates the merge iterator for the current day.
func (d *DynamoAggregatedReportFeedIterator) setupMergeIteratorForCurrentDay() bool {
	iters, shardIDs := d.buildShardIterators()

	if len(iters) == 0 {
		return false // Nothing in this day
	}

	// Create the day-level merge iterator using the standard extractors
	d.merged = NewMergeIterator(iters, shardIDs, tsFromFinalizedAt, itemToKey, secondaryKeyFromCommitteeMsg)
	d.mergedHasMore = d.merged.HasMore()
	return true
}

// buildShardIterators creates iterators for all active shards in the current day.
func (d *DynamoAggregatedReportFeedIterator) buildShardIterators() ([]ItemIterator, []string) {
	var iters []ItemIterator
	var shardIDs []string

	for _, shard := range d.shards {
		// Skip shards marked exhausted in the token
		if d.isShardExhausted(shard) {
			continue
		}

		prev := d.getShardToken(shard)
		if it := d.shardIteratorFactory(d.currentDay, shard, prev); it != nil {
			iters = append(iters, it)
			shardIDs = append(shardIDs, shard)
		}
	}

	return iters, shardIDs
}

// isShardExhausted checks if a shard is marked as exhausted in the token.
func (d *DynamoAggregatedReportFeedIterator) isShardExhausted(shard string) bool {
	if d.inputToken == nil || d.inputToken.Tokens == nil {
		return false
	}

	if t, ok := d.inputToken.Tokens[shard]; ok && !t.HasMore {
		return true
	}

	return false
}

// getShardToken retrieves the pagination token for a specific shard.
func (d *DynamoAggregatedReportFeedIterator) getShardToken(shard string) *SinglePartitionPaginationToken {
	if d.inputToken == nil || d.inputToken.Tokens == nil {
		return nil
	}

	if t, ok := d.inputToken.Tokens[shard]; ok && t.HasMore {
		return &t
	}

	return nil
}

// updateCursors merges per-shard cursors using Option B semantics (no dupes, no rewinds).
func (d *DynamoAggregatedReportFeedIterator) updateCursors() {
	if d.merged == nil {
		return
	}
	pending := d.merged.ShardPending()

	// Start from existing cursors (carried from incoming token + previous page work).
	acc := make(map[string]SinglePartitionPaginationToken, len(d.accumCursors))
	for k, v := range d.accumCursors {
		acc[k] = v
	}

	// For shards that produced something during this page/day, update:
	for shard, lastEvaluatedKey := range d.merged.Cursors() {
		if pending[shard] {
			tok := keyToToken(lastEvaluatedKey) // GSIPK/GSISK -> DayCommitteePartition/TimeSeqMessage (+extras)
			tok.HasMore = true
			acc[shard] = tok
		} else {
			// Shard exhausted for this day -> mark HasMore=false and clear keys.
			prev := acc[shard]
			prev.HasMore = false
			prev.DayCommitteePartition = ""
			prev.TimeSeqMessage = ""
			prev.CommitteeIDMessageID = ""
			prev.FinalizedAt = ""
			acc[shard] = prev
		}
	}

	d.accumCursors = acc
	d.mergedHasMore = d.merged.HasMore()
}

// NextPageToken returns a token iff there's definitely more work
// (this day's heap still has items OR more days left).
func (d *DynamoAggregatedReportFeedIterator) NextPageToken() *AggregatedReportPaginationToken {
	// If we never produced an item, prefer the day iterator’s Day()
	lastDay := d.currentDay
	if lastDay == "" {
		lastDay = d.dayIter.Day()
	}

	if !d.mergedHasMore && d.dayIter.Done() {
		return nil
	}
	if len(d.accumCursors) == 0 && d.dayIter.Done() {
		return nil
	}

	// Copy cursors to avoid external mutation.
	out := make(map[string]SinglePartitionPaginationToken, len(d.accumCursors))
	for k, v := range d.accumCursors {
		out[k] = v
	}
	return &AggregatedReportPaginationToken{
		LastDay: lastDay,
		Tokens:  out,
	}
}
