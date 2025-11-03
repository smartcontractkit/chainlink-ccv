package storage

import (
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
)

// WithCondition wraps a storage with its read condition.
type WithCondition struct {
	Storage   common.IndexerStorage
	Condition ReadCondition
}

// ReadConditionType defines when a storage should be read from.
type ReadConditionType string

const (
	// ReadAlways means the storage is always eligible for reads.
	ReadAlways ReadConditionType = "always"
	// ReadTimeRange means the storage is only read when query time range matches the condition.
	ReadTimeRange ReadConditionType = "time_range"
	// ReadRecent means the storage is only read for recent data (within a duration from now).
	ReadRecent ReadConditionType = "recent"
	// ReadNever means the storage is never read from (write-only).
	ReadNever ReadConditionType = "never"
)

// ReadCondition defines when a storage backend should be read from.
type ReadCondition struct {
	Type ReadConditionType
	// For ReadTimeRange: the start of the time range this storage covers (unix timestamp).
	// nil means no lower bound.
	StartUnix *int64
	// For ReadTimeRange: the end of the time range this storage covers (unix timestamp).
	// nil means no upper bound.
	EndUnix *int64
	// For ReadRecent: the duration from now that this storage covers.
	// For example, time.Hour means "only read if querying data from the last hour".
	LookbackWindowDuration time.Duration
}

// AlwaysRead creates a read condition that always allows reads.
func AlwaysRead() ReadCondition {
	return ReadCondition{Type: ReadAlways}
}

// NeverRead creates a read condition that never allows reads (write-only).
func NeverRead() ReadCondition {
	return ReadCondition{Type: ReadNever}
}

// TimeRangeRead creates a read condition that only allows reads within a specific time range.
// Pass nil for startUnix or endUnix to indicate no bound on that side.
func TimeRangeRead(startUnix, endUnix *int64) ReadCondition {
	return ReadCondition{
		Type:      ReadTimeRange,
		StartUnix: startUnix,
		EndUnix:   endUnix,
	}
}

// RecentRead creates a read condition that only allows reads for recent data.
// For example, RecentRead(time.Hour) means "only read if querying data from the last hour".
// This is useful for hot storage that contains recent data where the time boundary
// is relative to "now" rather than a fixed timestamp.
func RecentRead(duration time.Duration) ReadCondition {
	return ReadCondition{
		Type:                   ReadRecent,
		LookbackWindowDuration: duration,
	}
}

// shouldRead determines if this storage should be read based on the condition and query parameters.
// For queries without time range (like GetCCVData), start and end should both be nil.
func (rc ReadCondition) shouldRead(queryStart, queryEnd *int64) bool {
	switch rc.Type {
	case ReadAlways:
		return true
	case ReadNever:
		return false
	case ReadTimeRange:
		// If no query time range is provided (like GetCCVData), always try to read
		if queryStart == nil && queryEnd == nil {
			return true
		}

		// Check if the query time range overlaps with the storage's time range
		// Query range: [queryStart, queryEnd]
		// Storage range: [rc.StartUnix, rc.EndUnix]

		// If storage has a start time and query has an end time, check if query ends before storage starts
		if rc.StartUnix != nil && queryEnd != nil && *queryEnd < *rc.StartUnix {
			return false
		}

		// If storage has an end time and query has a start time, check if query starts after storage ends
		if rc.EndUnix != nil && queryStart != nil && *queryStart > *rc.EndUnix {
			return false
		}

		// Otherwise, there's overlap or no bounds, so read from this storage
		return true
	case ReadRecent:
		// If no query time range is provided (like GetCCVData), always try to read
		if queryStart == nil && queryEnd == nil {
			return true
		}

		// Calculate the time boundary for "recent" data
		// Recent data is from (now - duration) to now
		now := time.Now().UnixMilli() // Use milliseconds to match query timestamps
		recentStart := now - rc.LookbackWindowDuration.Milliseconds()

		// Check if the query time range overlaps with the recent period
		// Query range: [queryStart, queryEnd]
		// Recent range: [recentStart, now]

		// If query ends before recent period starts, skip this storage
		if queryEnd != nil && *queryEnd < recentStart {
			return false
		}

		// If query starts after now, skip this storage (querying future data)
		if queryStart != nil && *queryStart > now {
			return false
		}

		// Otherwise, there's overlap with the recent period
		return true
	default:
		// Unknown type, default to always read
		return true
	}
}
