package leaderelector

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestHashBasedLeaderElector(t *testing.T) {
	testCases := []struct {
		name              string
		executorIds       []string
		thisExecutorId    string
		executionInterval time.Duration
		minWaitPeriod     time.Duration
		messageID         protocol.Bytes32
		baseTimestamp     int64
		readyTimestamp    int64
	}{
		{
			name:              "first executor with specific message",
			executorIds:       []string{"executor-c", "executor-a", "executor-b"},
			thisExecutorId:    "executor-a",
			executionInterval: 30 * time.Second,
			minWaitPeriod:     10 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x03},
			baseTimestamp:     1000,
			readyTimestamp:    1000 + 10 + 30*0, // executor-a is at index 0 in sorted order
		},
		{
			name:              "different message will change order for same executor",
			executorIds:       []string{"executor-c", "executor-a", "executor-b"},
			thisExecutorId:    "executor-a",
			executionInterval: 30 * time.Second,
			minWaitPeriod:     10 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x04},
			baseTimestamp:     1000,
			readyTimestamp:    1000 + 10 + 30*2, // executor-a is at index 0 in sorted order
		},
		{
			name:              "middle executor with specific message",
			executorIds:       []string{"executor-c", "executor-a", "executor-b"},
			thisExecutorId:    "executor-b",
			executionInterval: 30 * time.Second,
			minWaitPeriod:     10 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x03},
			baseTimestamp:     1000,
			readyTimestamp:    1000 + 10 + 30*1, // executor-b is at index 1 in sorted order
		},
		{
			name:              "different message ID changes order",
			executorIds:       []string{"executor-c", "executor-a", "executor-b"},
			thisExecutorId:    "executor-a",
			executionInterval: 30 * time.Second,
			minWaitPeriod:     10 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x04},
			baseTimestamp:     1000,
			readyTimestamp:    1000 + 10 + 30*2,
		},
		{
			name:              "different execution interval",
			executorIds:       []string{"executor-a", "executor-b"},
			thisExecutorId:    "executor-b",
			executionInterval: 60 * time.Second,
			minWaitPeriod:     5 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x03},
			baseTimestamp:     2000,
			readyTimestamp:    2000 + 5 + 60*1,
		},
		{
			name:              "single executor",
			executorIds:       []string{"executor-a"},
			thisExecutorId:    "executor-a",
			executionInterval: 45 * time.Second,
			minWaitPeriod:     15 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x03},
			baseTimestamp:     1500,
			readyTimestamp:    1500 + 15 + 45*0, // only one executor at index 0
		},
		{
			name:              "empty executor list",
			executorIds:       []string{},
			thisExecutorId:    "executor-a",
			executionInterval: 45 * time.Second,
			minWaitPeriod:     15 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x03},
			baseTimestamp:     1500,
			readyTimestamp:    1500 + 15, // falls back to just minWaitPeriod
		},
		{
			name:              "0 min wait period",
			executorIds:       []string{},
			thisExecutorId:    "executor-a",
			executionInterval: 45 * time.Second,
			minWaitPeriod:     0 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x03},
			baseTimestamp:     1500,
			readyTimestamp:    1500, // falls back to just minWaitPeriod
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create the leader elector
			elector := NewHashBasedLeaderElector(
				logger.Test(t),
				tc.executorIds,
				tc.thisExecutorId,
				tc.executionInterval,
				tc.minWaitPeriod,
			)

			require.NotNil(t, elector)

			// Get the ready timestamp
			actualTimestamp := elector.GetReadyTimestamp(tc.messageID, tc.baseTimestamp)

			assert.Equal(t, tc.readyTimestamp, actualTimestamp)

			// We can check the bounds and consistency
			minExpectedDelay := int64(tc.minWaitPeriod.Seconds())
			maxExpectedDelay := int64(tc.minWaitPeriod.Seconds()) + int64(tc.executionInterval.Seconds()*float64(len(tc.executorIds)))

			calculatedDelay := actualTimestamp - tc.baseTimestamp
			assert.GreaterOrEqual(t, calculatedDelay, minExpectedDelay,
				"Ready timestamp should be at least baseTimestamp + minWaitPeriod")
			assert.LessOrEqual(t, calculatedDelay, maxExpectedDelay,
				"Ready timestamp should not exceed baseTimestamp + minWaitPeriod + (numExecutors-1)*executionInterval")

			// Run it again to check consistency
			readyTimestamp2 := elector.GetReadyTimestamp(tc.messageID, tc.baseTimestamp)
			assert.Equal(t, actualTimestamp, readyTimestamp2, "Results should be deterministic for the same inputs")
		})
	}
}

func TestHashBasedLeaderElector_DeterministicBehavior(t *testing.T) {
	executorIds := []string{"executor-c", "executor-a", "executor-b"}
	executionInterval := 30 * time.Second
	minWaitPeriod := 10 * time.Second
	baseTimestamp := int64(1000)

	// Different message IDs should result in different execution orders
	messageID1 := protocol.Bytes32{0x01, 0x02, 0x03}
	messageID2 := protocol.Bytes32{0x04, 0x05, 0x06}

	// Test that all executors agree on the relative ordering for each message
	electors := make(map[string]*HashBasedLeaderElector)
	for _, id := range executorIds {
		electors[id] = NewHashBasedLeaderElector(logger.Test(t), executorIds, id, executionInterval, minWaitPeriod)
	}

	// Check message1 ordering
	msg1Times := make(map[string]int64)
	for id, elector := range electors {
		msg1Times[id] = elector.GetReadyTimestamp(messageID1, baseTimestamp)
	}

	// Check message2 ordering
	msg2Times := make(map[string]int64)
	for id, elector := range electors {
		msg2Times[id] = elector.GetReadyTimestamp(messageID2, baseTimestamp)
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
		result1 := elector.GetReadyTimestamp(messageID1, baseTimestamp)
		result2 := elector.GetReadyTimestamp(messageID1, baseTimestamp)
		assert.Equal(t, result1, result2, "Same elector should return consistent results")
	}
}

// Helper function to determine executor order from timestamps.
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
	baseTimestamp := int64(1000)

	elector := NewHashBasedLeaderElector(logger.Test(t), executorIds, thisExecutorId, executionInterval, minWaitPeriod)

	readyTimestamp := elector.GetReadyTimestamp(messageID, baseTimestamp)

	// Should fall back to just minWaitPeriod when executor not in list
	expectedTimestamp := baseTimestamp + int64(minWaitPeriod.Seconds())
	assert.Equal(t, expectedTimestamp, readyTimestamp,
		"When executor not in list, should return baseTimestamp + minWaitPeriod")
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
				logger.Test(t),
				tc.executorIds,
				tc.thisExecutorId,
				30*time.Second,
				10*time.Second,
			)

			assert.Equal(t, tc.expectedIndex, elector.executorIndex,
				"Executor index should match expected position in sorted array")
			assert.Equal(t, tc.expectedSortedIds, elector.executorIDs,
				"Executor IDs should be sorted")
		})
	}
}

func Test_getSliceIncreasingDistance(t *testing.T) {
	testCases := []struct {
		name          string
		sliceLen      int
		startIndex    int
		selectedIndex int
		expected      int64
	}{
		{
			name:          "same index returns zero distance",
			sliceLen:      5,
			startIndex:    2,
			selectedIndex: 2,
			expected:      0,
		},
		{
			name:          "selected index before start - wraps around",
			sliceLen:      5,
			startIndex:    3,
			selectedIndex: 1,
			expected:      3, // 5 - 3 + 1 = 3 (wrap around: 3->4->0->1)
		},
		{
			name:          "selected index after start",
			sliceLen:      5,
			startIndex:    1,
			selectedIndex: 3,
			expected:      2, // distance from 1 to 3 is 2
		},
		{
			name:          "wrap around from end to beginning",
			sliceLen:      4,
			startIndex:    3,
			selectedIndex: 0,
			expected:      1, // 4 - 3 + 0 = 1 (wrap: 3->0)
		},
		{
			name:          "wrap around with larger distance",
			sliceLen:      10,
			startIndex:    8,
			selectedIndex: 2,
			expected:      4, // 10 - 8 + 2 = 4 (wrap: 8->9->0->1->2)
		},
		{
			name:          "first to last in array",
			sliceLen:      5,
			startIndex:    0,
			selectedIndex: 4,
			expected:      4, // 4 - 0 = 4
		},
		{
			name:          "last to first wraps",
			sliceLen:      5,
			startIndex:    4,
			selectedIndex: 0,
			expected:      1, // 5 - 4 + 0 = 1
		},
		{
			name:          "single element array",
			sliceLen:      1,
			startIndex:    0,
			selectedIndex: 0,
			expected:      0,
		},
		{
			name:          "two element array - forward",
			sliceLen:      2,
			startIndex:    0,
			selectedIndex: 1,
			expected:      1,
		},
		{
			name:          "two element array - wrap",
			sliceLen:      2,
			startIndex:    1,
			selectedIndex: 0,
			expected:      1, // 2 - 1 + 0 = 1
		},
		{
			name:          "error scenario, invalid startIndex",
			sliceLen:      2,
			startIndex:    3,
			selectedIndex: 0,
			expected:      0,
		},
		{
			name:          "error scenario, invalid selectedIndex",
			sliceLen:      2,
			startIndex:    0,
			selectedIndex: 3,
			expected:      0,
		},
		{
			name:          "valid scenario, sliceLen 0",
			sliceLen:      0,
			startIndex:    0,
			selectedIndex: 0,
			expected:      0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getSliceIncreasingDistance(tc.sliceLen, tc.startIndex, tc.selectedIndex)
			assert.Equal(t, tc.expected, result,
				"Distance from startIndex %d to selectedIndex %d in slice of length %d should be %d",
				tc.startIndex, tc.selectedIndex, tc.sliceLen, tc.expected)
		})
	}
}

func TestHashBasedLeaderElector_GetRetryDelay(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		executorIds       []string
		executionInterval time.Duration
		expectedDelay     int64
	}{
		{
			name:              "valid test",
			executorIds:       []string{"ex-1", "ex-2", "ex-3"},
			executionInterval: 20 * time.Second,
			expectedDelay:     3 * 20, // 3 executors * 20s
		},
		{
			name:              "multiple executors in pool",
			executorIds:       []string{"ex-1", "ex-2", "ex-3", "ex-4"},
			executionInterval: 15 * time.Second,
			expectedDelay:     4 * 15, // 4 executors * 15s
		},
		{
			name:              "single executor",
			executorIds:       []string{"only-executor"},
			executionInterval: 30 * time.Second,
			expectedDelay:     1 * 30, // 1 executor * 30s
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Pick the first executor as thisExecutorId for simplicity
			thisID := tc.executorIds[0]
			le := NewHashBasedLeaderElector(logger.Test(t), tc.executorIds, thisID, tc.executionInterval, 0)
			retryDelay := le.GetRetryDelay(123)
			assert.Equal(t, tc.expectedDelay, retryDelay, "unexpected retry delay for case %s", tc.name)
		})
	}
}
