package leaderelector

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestHashBasedLeaderElectorSingleChain(t *testing.T) {
	testCases := []struct {
		name              string
		executorIds       []string
		thisExecutorId    string
		executionInterval time.Duration
		messageID         protocol.Bytes32
		chainSel          protocol.ChainSelector
		baseTimestamp     time.Time
		readyTimestamp    time.Time
	}{
		{
			name:              "first executor with specific message",
			executorIds:       []string{"executor-c", "executor-a", "executor-b"},
			thisExecutorId:    "executor-a",
			executionInterval: 30 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x03},
			baseTimestamp:     time.Unix(1000, 0),
			readyTimestamp:    time.Unix(1000+30*0, 0), // executor-a is at index 0 in sorted order
		},
		{
			name:              "different message will change order for same executor",
			executorIds:       []string{"executor-c", "executor-a", "executor-b"},
			thisExecutorId:    "executor-a",
			executionInterval: 30 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x04},
			baseTimestamp:     time.Unix(1000, 0),
			readyTimestamp:    time.Unix(1000+30*2, 0), // executor-a is at index 0 in sorted order
		},
		{
			name:              "middle executor with specific message",
			executorIds:       []string{"executor-c", "executor-a", "executor-b"},
			thisExecutorId:    "executor-b",
			executionInterval: 30 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x03},
			baseTimestamp:     time.Unix(1000, 0),
			readyTimestamp:    time.Unix(1000+30*1, 0), // executor-b is at index 1 in sorted order
		},
		{
			name:              "different message ID changes order",
			executorIds:       []string{"executor-c", "executor-a", "executor-b"},
			thisExecutorId:    "executor-a",
			executionInterval: 30 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x04},
			baseTimestamp:     time.Unix(1000, 0),
			readyTimestamp:    time.Unix(1000+30*2, 0),
		},
		{
			name:              "different execution interval",
			executorIds:       []string{"executor-a", "executor-b"},
			thisExecutorId:    "executor-b",
			executionInterval: 60 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x03},
			baseTimestamp:     time.Unix(2000, 0),
			readyTimestamp:    time.Unix(2000+60*1, 0),
		},
		{
			name:              "single executor",
			executorIds:       []string{"executor-a"},
			thisExecutorId:    "executor-a",
			executionInterval: 45 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x03},
			baseTimestamp:     time.Unix(1500, 0),
			readyTimestamp:    time.Unix(1500+45*0, 0), // only one executor at index 0
		},
		{
			name:              "empty executor list",
			executorIds:       []string{},
			thisExecutorId:    "executor-a",
			executionInterval: 45 * time.Second,
			messageID:         protocol.Bytes32{0x01, 0x02, 0x03},
			baseTimestamp:     time.Unix(1500, 0),
			readyTimestamp:    time.Unix(1500, 0), // falls back to just baseTimestamp
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create the leader elector
			elector := NewHashBasedLeaderElector(
				logger.Test(t),
				map[protocol.ChainSelector][]string{tc.chainSel: tc.executorIds},
				tc.thisExecutorId,
				map[protocol.ChainSelector]time.Duration{tc.chainSel: tc.executionInterval},
			)

			require.NotNil(t, elector)

			// Get the ready timestamp
			actualTimestamp := elector.GetReadyTimestamp(tc.messageID, tc.chainSel, tc.baseTimestamp)

			require.Equal(t, tc.readyTimestamp, actualTimestamp)

			// We can check the bounds and consistency
			minExpectedDelay := 0 * time.Second
			maxExpectedDelay := tc.executionInterval * time.Duration(len(tc.executorIds))

			calculatedDelay := actualTimestamp.Sub(tc.baseTimestamp)
			require.GreaterOrEqual(t, calculatedDelay, minExpectedDelay,
				"Ready timestamp should be at least baseTimestamp")
			require.LessOrEqual(t, calculatedDelay, maxExpectedDelay,
				"Ready timestamp should not exceed baseTimestamp + (numExecutors-1)*executionInterval")

			// Run it again to check consistency
			readyTimestamp2 := elector.GetReadyTimestamp(tc.messageID, tc.chainSel, tc.baseTimestamp)
			require.Equal(t, actualTimestamp, readyTimestamp2, "Results should be deterministic for the same inputs")
		})
	}
}

func TestHashBasedLeaderElector_DeterministicBehavior(t *testing.T) {
	sel := protocol.ChainSelector(1)
	executorIds := map[protocol.ChainSelector][]string{sel: {"executor-c", "executor-a", "executor-b"}}
	executionInterval := map[protocol.ChainSelector]time.Duration{sel: 30 * time.Second}
	baseTimestamp := time.Unix(100, 0)

	// Different message IDs should result in different execution orders
	messageID1 := protocol.Bytes32{0x01, 0x02, 0x03}
	messageID2 := protocol.Bytes32{0x04, 0x05, 0x06}

	// Test that all executors agree on the relative ordering for each message
	electors := make(map[string]*HashBasedLeaderElector)
	for _, id := range executorIds[sel] {
		electors[id] = NewHashBasedLeaderElector(logger.Test(t), executorIds, id, executionInterval)
	}

	// Check message1 ordering
	msg1Times := make(map[string]time.Time)
	for id, elector := range electors {
		msg1Times[id] = elector.GetReadyTimestamp(messageID1, sel, baseTimestamp)
	}

	// Check message2 ordering
	msg2Times := make(map[string]time.Time)
	for id, elector := range electors {
		msg2Times[id] = elector.GetReadyTimestamp(messageID2, sel, baseTimestamp)
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
		result1 := elector.GetReadyTimestamp(messageID1, sel, baseTimestamp)
		result2 := elector.GetReadyTimestamp(messageID1, sel, baseTimestamp)
		require.Equal(t, result1, result2, "Same elector should return consistent results")
	}
}

// Helper function to determine executor order from timestamps.
func getExecutorOrderFromTimestamps(timestamps map[string]time.Time) []string {
	type executorTime struct {
		id        string
		timestamp time.Time
	}

	ordered := make([]executorTime, 0, len(timestamps))
	for id, ts := range timestamps {
		ordered = append(ordered, executorTime{id, ts})
	}

	// Sort by timestamp
	slices.SortFunc(ordered, func(a, b executorTime) int {
		if a.timestamp.Before(b.timestamp) {
			return -1
		}
		if a.timestamp.After(b.timestamp) {
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
	sel := protocol.ChainSelector(1)
	executorIds := map[protocol.ChainSelector][]string{sel: {"executor-a", "executor-b"}}
	thisExecutorId := "executor-not-in-list"
	executionInterval := map[protocol.ChainSelector]time.Duration{sel: 30 * time.Second}
	messageID := protocol.Bytes32{0x01, 0x02, 0x03}
	baseTimestamp := time.Unix(1000, 0)

	elector := NewHashBasedLeaderElector(logger.Test(t), executorIds, thisExecutorId, executionInterval)

	readyTimestamp := elector.GetReadyTimestamp(messageID, sel, baseTimestamp)

	// Should fall back to just minWaitPeriod when executor not in list
	expectedTimestamp := baseTimestamp
	require.Equal(t, expectedTimestamp, readyTimestamp,
		"When executor not in list, should return baseTimestamp + minWaitPeriod")
}

func TestHashBasedLeaderElector_ExecutorIndexCalculation_MultiSelector(t *testing.T) {
	type testConfig struct {
		executorIds       map[protocol.ChainSelector][]string
		thisExecutorId    string
		expectedIndices   map[protocol.ChainSelector]int
		expectedSortedIds map[protocol.ChainSelector][]string
	}
	tests := []struct {
		name string
		cfg  testConfig
	}{
		{
			name: "single selector, unsorted list gets sorted",
			cfg: testConfig{
				executorIds: map[protocol.ChainSelector][]string{
					1: {"executor-z", "executor-a", "executor-m"},
				},
				thisExecutorId: "executor-m",
				expectedIndices: map[protocol.ChainSelector]int{
					1: 1, // executor-m is at index 1 after sort
				},
				expectedSortedIds: map[protocol.ChainSelector][]string{
					1: {"executor-a", "executor-m", "executor-z"},
				},
			},
		},
		{
			name: "multiple selectors, all sorted independently",
			cfg: testConfig{
				executorIds: map[protocol.ChainSelector][]string{
					1: {"executor-c", "executor-a", "executor-b"},
					2: {"x", "a", "m", "z"},
				},
				thisExecutorId: "executor-b",
				expectedIndices: map[protocol.ChainSelector]int{
					1: 1,  // executor-b at index 1 after sort (["executor-a", "executor-b", "executor-c"])
					2: -1, // executor-b not present in selector 2
				},
				expectedSortedIds: map[protocol.ChainSelector][]string{
					1: {"executor-a", "executor-b", "executor-c"},
					2: {"a", "m", "x", "z"},
				},
			},
		},
		{
			name: "multi selector, unique executor per selector",
			cfg: testConfig{
				executorIds: map[protocol.ChainSelector][]string{
					42: {"alpha"},
					35: {"b", "a", "d", "c"},
				},
				thisExecutorId: "a",
				expectedIndices: map[protocol.ChainSelector]int{
					42: -1, // "a" not present in selector 42
					35: 0,  // "a" is index 0 after sort ["a", "b", "c", "d"]
				},
				expectedSortedIds: map[protocol.ChainSelector][]string{
					42: {"alpha"},
					35: {"a", "b", "c", "d"},
				},
			},
		},
		{
			name: "multiple selectors, duplicate executor id in both selectors",
			cfg: testConfig{
				executorIds: map[protocol.ChainSelector][]string{
					13: {"exec-b", "exec-a", "exec-c"},
					99: {"exec-c", "exec-b", "exec-a"},
				},
				thisExecutorId: "exec-c",
				expectedIndices: map[protocol.ChainSelector]int{
					13: 2, // ["exec-a", "exec-b", "exec-c"], exec-c is index 2
					99: 2, // ["exec-a", "exec-b", "exec-c"], exec-c is index 2
				},
				expectedSortedIds: map[protocol.ChainSelector][]string{
					13: {"exec-a", "exec-b", "exec-c"},
					99: {"exec-a", "exec-b", "exec-c"},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			intervals := make(map[protocol.ChainSelector]time.Duration)
			for sel := range tc.cfg.executorIds {
				intervals[sel] = 10 * time.Second
			}
			elector := NewHashBasedLeaderElector(
				logger.Test(t),
				tc.cfg.executorIds,
				tc.cfg.thisExecutorId,
				intervals,
			)

			for sel, expectedSorted := range tc.cfg.expectedSortedIds {
				require.Equal(t, expectedSorted, elector.executorIDs[sel], "ExecutorIDs should be sorted for selector %d", sel)
			}
			for sel, expectedIdx := range tc.cfg.expectedIndices {
				require.Equal(t, expectedIdx, elector.executorIndices[sel], "Executor index should match for selector %d", sel)
			}
		})
	}
}

func TestHashBasedLeaderElector_ExecutorIndexCalculation(t *testing.T) {
	testCases := []struct {
		name              string
		executorIds       []string
		thisExecutorId    string
		chainSel          protocol.ChainSelector
		expectedIndex     int
		expectedSortedIds []string
	}{
		{
			name:              "unsorted list gets sorted",
			executorIds:       []string{"executor-z", "executor-a", "executor-m"},
			chainSel:          protocol.ChainSelector(1),
			thisExecutorId:    "executor-m",
			expectedIndex:     1, // executor-m is at index 1 in sorted list [executor-a, executor-m, executor-z]
			expectedSortedIds: []string{"executor-a", "executor-m", "executor-z"},
		},
		{
			name:              "already sorted list",
			executorIds:       []string{"executor-a", "executor-b", "executor-c"},
			chainSel:          protocol.ChainSelector(1),
			thisExecutorId:    "executor-b",
			expectedIndex:     1,
			expectedSortedIds: []string{"executor-a", "executor-b", "executor-c"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			elector := NewHashBasedLeaderElector(
				logger.Test(t),
				map[protocol.ChainSelector][]string{tc.chainSel: tc.executorIds},
				tc.thisExecutorId,
				map[protocol.ChainSelector]time.Duration{tc.chainSel: 30 * time.Second},
			)

			require.Equal(t, tc.expectedIndex, elector.executorIndices[tc.chainSel],
				"Executor index should match expected position in sorted array")
			require.Equal(t, tc.expectedSortedIds, elector.executorIDs[tc.chainSel],
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
		expected      int
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
			require.Equal(t, tc.expected, result,
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
		chainSel          protocol.ChainSelector
		expectedDelay     time.Duration
	}{
		{
			name:              "valid test",
			executorIds:       []string{"ex-1", "ex-2", "ex-3"},
			executionInterval: 20 * time.Second,
			chainSel:          protocol.ChainSelector(1),
			expectedDelay:     3 * 20 * time.Second, // 3 executors * 20s
		},
		{
			name:              "multiple executors in pool",
			executorIds:       []string{"ex-1", "ex-2", "ex-3", "ex-4"},
			executionInterval: 15 * time.Second,
			chainSel:          protocol.ChainSelector(1),
			expectedDelay:     4 * 15 * time.Second, // 4 executors * 15s
		},
		{
			name:              "single executor",
			executorIds:       []string{"only-executor"},
			executionInterval: 30 * time.Second,
			chainSel:          protocol.ChainSelector(1),
			expectedDelay:     1 * 30 * time.Second, // 1 executor * 30s
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Pick the first executor as thisExecutorId for simplicity
			thisID := tc.executorIds[0]
			le := NewHashBasedLeaderElector(
				logger.Test(t),
				map[protocol.ChainSelector][]string{tc.chainSel: tc.executorIds},
				thisID,
				map[protocol.ChainSelector]time.Duration{tc.chainSel: tc.executionInterval})
			retryDelay := le.GetRetryDelay(tc.chainSel)
			require.Equal(t, tc.expectedDelay, retryDelay, "unexpected retry delay for case %s", tc.name)
		})
	}
}
