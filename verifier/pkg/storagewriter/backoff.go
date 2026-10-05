package storagewriter

import "time"

const (
	// DefaultBackoffFactor is the multiplier applied to the base storage-write retry
	// delay on each successive failed attempt. A factor of 2 doubles the wait each time.
	DefaultBackoffFactor = 2

	// DefaultBackoffMax caps the truncated exponential backoff so consecutive retries
	// never space out unbounded. Without a cap, a down aggregator would hold a message's
	// finality open for as long as its retry window allows while retries grow exponentially.
	DefaultBackoffMax = 1 * time.Minute
)
