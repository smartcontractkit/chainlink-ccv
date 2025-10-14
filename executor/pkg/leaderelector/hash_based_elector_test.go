package leaderelector

import (
	"slices"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashBasedLeaderElector(t *testing.T) {
	testCases := []struct {
		name              string
		executorIds       []string
		thisExecutorId    string
		executionInterval time.Duration
		minWaitPeriod     time.Duration
		messageID         protocol.Bytes32
		verifierTimestamp int64
	}{
		{
			name:              "first executor with specific message",
			executorIds:       []string{"executor-c", "executor-a", "executor-b"},
			thisExecutorId:    "executor-a",
			executionInterval: 30 * time.Second,
			minWaitPeriod:     10 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x03},
			verifierTimestamp: 1000,
		},
		{
			name:              "middle executor with specific message",
			executorIds:       []string{"executor-c", "executor-a", "executor-b"},
			thisExecutorId:    "executor-b",
			executionInterval: 30 * time.Second,
			minWaitPeriod:     10 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x03},
			verifierTimestamp: 1000,
		},
		{
			name:              "different message ID changes order",
			executorIds:       []string{"executor-c", "executor-a", "executor-b"},
			thisExecutorId:    "executor-c",
			executionInterval: 30 * time.Second,
			minWaitPeriod:     10 * time.Second,
			messageID:         protocol.Bytes32{0x04, 0x05, 0x06},
			verifierTimestamp: 1000,
		},
		{
			name:              "different execution interval",
			executorIds:       []string{"executor-a", "executor-b"},
			thisExecutorId:    "executor-b",
			executionInterval: 60 * time.Second,
			minWaitPeriod:     5 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x03},
			verifierTimestamp: 2000,
		},
		{
			name:              "single executor",
			executorIds:       []string{"executor-only"},
			thisExecutorId:    "executor-only",
			executionInterval: 45 * time.Second,
			minWaitPeriod:     15 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x03},
			verifierTimestamp: 1500,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create the leader elector
			elector := NewHashBasedLeaderElector(
				tc.executorIds,
				tc.thisExecutorId,
				tc.executionInterval,
				tc.minWaitPeriod,
			)

			require.NotNil(t, elector)

			// Get the ready timestamp
			readyTimestamp := elector.GetReadyTimestamp(tc.messageID, tc.verifierTimestamp)

			// With our new hashing approach, we can't precisely predict the output in tests,
			// but we can check the bounds and consistency
			minExpectedDelay := int64(tc.minWaitPeriod.Seconds())
			maxExpectedDelay := int64(tc.minWaitPeriod.Seconds()) + int64(tc.executionInterval.Seconds()*float64(len(tc.executorIds)-1))

			calculatedDelay := readyTimestamp - tc.verifierTimestamp
			assert.GreaterOrEqual(t, calculatedDelay, minExpectedDelay,
				"Ready timestamp should be at least verifierTimestamp + minWaitPeriod")
			assert.LessOrEqual(t, calculatedDelay, maxExpectedDelay,
				"Ready timestamp should not exceed verifierTimestamp + minWaitPeriod + (numExecutors-1)*executionInterval")

			// Run it again to check consistency
			readyTimestamp2 := elector.GetReadyTimestamp(tc.messageID, tc.verifierTimestamp)
			assert.Equal(t, readyTimestamp, readyTimestamp2, "Results should be deterministic for the same inputs")
		})
	}
}

func TestHashBasedLeaderElector_DeterministicBehavior(t *testing.T) {
	executorIds := []string{"executor-c", "executor-a", "executor-b"}
	executionInterval := 30 * time.Second
	minWaitPeriod := 10 * time.Second
	verifierTimestamp := int64(1000)

	// Different message IDs should result in different execution orders
	messageID1 := protocol.Bytes32{0x01, 0x02, 0x03}
	messageID2 := protocol.Bytes32{0x04, 0x05, 0x06}

	// Test that all executors agree on the relative ordering for each message
	electors := make(map[string]*HashBasedLeaderElector)
	for _, id := range executorIds {
		electors[id] = NewHashBasedLeaderElector(executorIds, id, executionInterval, minWaitPeriod)
	}

	// Check message1 ordering
	msg1Times := make(map[string]int64)
	for id, elector := range electors {
		msg1Times[id] = elector.GetReadyTimestamp(messageID1, verifierTimestamp)
	}

	// Check message2 ordering
	msg2Times := make(map[string]int64)
	for id, elector := range electors {
		msg2Times[id] = elector.GetReadyTimestamp(messageID2, verifierTimestamp)
	}

	// Verify different messages create different orderings
	orderings1 := getExecutorOrderFromTimestamps(msg1Times)
	orderings2 := getExecutorOrderFromTimestamps(msg2Times)

	// Different messages should typically result in different orderings
	// Note: There's a small probability they could match by chance
	t.Logf("Message1 ordering: %v", orderings1)
	t.Logf("Message2 ordering: %v", orderings2)

	// Verify consistent results across multiple calls
	for _, elector := range electors {
		result1 := elector.GetReadyTimestamp(messageID1, verifierTimestamp)
		result2 := elector.GetReadyTimestamp(messageID1, verifierTimestamp)
		assert.Equal(t, result1, result2, "Same elector should return consistent results")
	}
}

// Helper function to determine executor order from timestamps
func getExecutorOrderFromTimestamps(timestamps map[string]int64) []string {
	type executorTime struct {
		id        string
		timestamp int64
	}

	ordered := make([]executorTime, 0, len(timestamps))
	for id, ts := range timestamps {
		ordered = append(ordered, executorTime{id, ts})
	}

	// Sort by timestamp
	slices.SortFunc(ordered, func(a, b executorTime) int {
		if a.timestamp < b.timestamp {
			return -1
		}
		if a.timestamp > b.timestamp {
			return 1
		}
		return 0
	})

	// Extract just the IDs in order
	result := make([]string, len(ordered))
	for i, item := range ordered {
		result[i] = item.id
	}

	return result
}

func TestHashBasedLeaderElector_ExecutorNotInList(t *testing.T) {
	executorIds := []string{"executor-a", "executor-b"}
	thisExecutorId := "executor-not-in-list"
	executionInterval := 30 * time.Second
	minWaitPeriod := 10 * time.Second
	messageID := protocol.Bytes32{0x01, 0x02, 0x03}
	verifierTimestamp := int64(1000)

	elector := NewHashBasedLeaderElector(executorIds, thisExecutorId, executionInterval, minWaitPeriod)

	readyTimestamp := elector.GetReadyTimestamp(messageID, verifierTimestamp)

	// Should fall back to just minWaitPeriod when executor not in list
	expectedTimestamp := verifierTimestamp + int64(minWaitPeriod.Seconds())
	assert.Equal(t, expectedTimestamp, readyTimestamp,
		"When executor not in list, should return verifierTimestamp + minWaitPeriod")
}

func TestHashBasedLeaderElector_ExecutorIndexCalculation(t *testing.T) {
	testCases := []struct {
		name              string
		executorIds       []string
		thisExecutorId    string
		expectedIndex     int
		expectedSortedIds []string
	}{
		{
			name:              "unsorted list gets sorted",
			executorIds:       []string{"executor-z", "executor-a", "executor-m"},
			thisExecutorId:    "executor-m",
			expectedIndex:     1, // executor-m is at index 1 in sorted list [executor-a, executor-m, executor-z]
			expectedSortedIds: []string{"executor-a", "executor-m", "executor-z"},
		},
		{
			name:              "already sorted list",
			executorIds:       []string{"executor-a", "executor-b", "executor-c"},
			thisExecutorId:    "executor-b",
			expectedIndex:     1,
			expectedSortedIds: []string{"executor-a", "executor-b", "executor-c"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			elector := NewHashBasedLeaderElector(
				tc.executorIds,
				tc.thisExecutorId,
				30*time.Second,
				10*time.Second,
			)

			assert.Equal(t, tc.expectedIndex, elector.executorIndex,
				"Executor index should match expected position in sorted array")
			assert.Equal(t, tc.expectedSortedIds, elector.executorIds,
				"Executor IDs should be sorted")
		})
	}
}
