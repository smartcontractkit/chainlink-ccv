package cursechecker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestCachedCurseChecker_CacheHit(t *testing.T) {
	tests := []struct {
		name                string
		cacheExpiry         time.Duration
		localChain          protocol.ChainSelector
		remoteChain         protocol.ChainSelector
		firstCallResult     []protocol.Bytes16
		firstCallError      error
		secondCallResult    []protocol.Bytes16
		secondCallError     error
		expectedFirstResult bool
		expectedCallCount   int
		sleepBetweenCalls   time.Duration
	}{
		{
			name:                "cache hit - cursed chain, reader called once",
			cacheExpiry:         1 * time.Second,
			localChain:          1,
			remoteChain:         2,
			firstCallResult:     []protocol.Bytes16{ChainSelectorToBytes16(2)},
			firstCallError:      nil,
			secondCallResult:    []protocol.Bytes16{}, // Should not be called
			secondCallError:     nil,
			expectedFirstResult: true,
			expectedCallCount:   1,
			sleepBetweenCalls:   0,
		},
		{
			name:                "cache hit - not cursed, reader called once",
			cacheExpiry:         1 * time.Second,
			localChain:          1,
			remoteChain:         2,
			firstCallResult:     []protocol.Bytes16{},
			firstCallError:      nil,
			secondCallResult:    []protocol.Bytes16{ChainSelectorToBytes16(2)}, // Should not be called
			secondCallError:     nil,
			expectedFirstResult: false,
			expectedCallCount:   1,
			sleepBetweenCalls:   0,
		},
		{
			name:                "cache hit - global curse, reader called once",
			cacheExpiry:         1 * time.Second,
			localChain:          1,
			remoteChain:         2,
			firstCallResult:     []protocol.Bytes16{GlobalCurseSubject},
			firstCallError:      nil,
			secondCallResult:    []protocol.Bytes16{}, // Should not be called
			secondCallError:     nil,
			expectedFirstResult: true,
			expectedCallCount:   1,
			sleepBetweenCalls:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			lggr, err := logger.New()
			assert.NoError(t, err)

			// Create mock reader
			mockReader := common.NewMockRMNRemoteReader(t)

			// Set up expectation for first call
			mockReader.EXPECT().
				GetRMNCursedSubjects(mock.Anything).
				Return(tt.firstCallResult, tt.firstCallError).
				Once()

			// Create cached curse checker
			checker := NewCachedCurseChecker(Params{
				Lggr: lggr,
				RmnReaders: map[protocol.ChainSelector]common.RMNRemoteReader{
					tt.localChain: mockReader,
				},
				CacheExpiry: tt.cacheExpiry,
			})

			// First call - should hit the reader
			result1 := checker.IsRemoteChainCursed(ctx, tt.localChain, tt.remoteChain)
			assert.Equal(t, tt.expectedFirstResult, result1)

			if tt.sleepBetweenCalls > 0 {
				time.Sleep(tt.sleepBetweenCalls)
			}

			// Second call - should hit the cache, not the reader
			result2 := checker.IsRemoteChainCursed(ctx, tt.localChain, tt.remoteChain)
			assert.Equal(t, tt.expectedFirstResult, result2)

			// Third call - verify cache is still being used
			result3 := checker.IsRemoteChainCursed(ctx, tt.localChain, tt.remoteChain)
			assert.Equal(t, tt.expectedFirstResult, result3)

			// Mock assertions will verify GetRMNCursedSubjects was only called once
		})
	}
}

func TestCachedCurseChecker_CacheExpiry(t *testing.T) {
	tests := []struct {
		name                 string
		cacheExpiry          time.Duration
		localChain           protocol.ChainSelector
		remoteChain          protocol.ChainSelector
		firstCallResult      []protocol.Bytes16
		secondCallResult     []protocol.Bytes16
		expectedFirstResult  bool
		expectedSecondResult bool
		sleepBetweenCalls    time.Duration
	}{
		{
			name:                 "cache expired - curse changes from true to false",
			cacheExpiry:          50 * time.Millisecond,
			localChain:           1,
			remoteChain:          2,
			firstCallResult:      []protocol.Bytes16{ChainSelectorToBytes16(2)},
			secondCallResult:     []protocol.Bytes16{},
			expectedFirstResult:  true,
			expectedSecondResult: false,
			sleepBetweenCalls:    100 * time.Millisecond,
		},
		{
			name:                 "cache expired - curse changes from false to true",
			cacheExpiry:          50 * time.Millisecond,
			localChain:           1,
			remoteChain:          2,
			firstCallResult:      []protocol.Bytes16{},
			secondCallResult:     []protocol.Bytes16{ChainSelectorToBytes16(2)},
			expectedFirstResult:  false,
			expectedSecondResult: true,
			sleepBetweenCalls:    100 * time.Millisecond,
		},
		{
			name:                 "cache expired - global curse added",
			cacheExpiry:          50 * time.Millisecond,
			localChain:           1,
			remoteChain:          2,
			firstCallResult:      []protocol.Bytes16{},
			secondCallResult:     []protocol.Bytes16{GlobalCurseSubject},
			expectedFirstResult:  false,
			expectedSecondResult: true,
			sleepBetweenCalls:    100 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			lggr, err := logger.New()
			assert.NoError(t, err)

			// Create mock reader
			mockReader := common.NewMockRMNRemoteReader(t)

			// Set up expectation for first call
			mockReader.EXPECT().
				GetRMNCursedSubjects(mock.Anything).
				Return(tt.firstCallResult, nil).
				Once()

			// Set up expectation for second call (after cache expiry)
			mockReader.EXPECT().
				GetRMNCursedSubjects(mock.Anything).
				Return(tt.secondCallResult, nil).
				Once()

			// Create cached curse checker
			checker := NewCachedCurseChecker(Params{
				Lggr: lggr,
				RmnReaders: map[protocol.ChainSelector]common.RMNRemoteReader{
					tt.localChain: mockReader,
				},
				CacheExpiry: tt.cacheExpiry,
			})

			// First call - should hit the reader
			result1 := checker.IsRemoteChainCursed(ctx, tt.localChain, tt.remoteChain)
			assert.Equal(t, tt.expectedFirstResult, result1)

			// Sleep to let cache expire
			time.Sleep(tt.sleepBetweenCalls)

			// Second call - cache expired, should hit the reader again
			result2 := checker.IsRemoteChainCursed(ctx, tt.localChain, tt.remoteChain)
			assert.Equal(t, tt.expectedSecondResult, result2)

			// Mock assertions will verify GetRMNCursedSubjects was called twice
		})
	}
}

func TestCachedCurseChecker_ErrorHandling(t *testing.T) {
	tests := []struct {
		name              string
		localChain        protocol.ChainSelector
		remoteChain       protocol.ChainSelector
		expectedErrorRes  bool
		expectedSecondRes bool
		secondResult      []protocol.Bytes16
	}{
		{
			name:              "reader error - assumes cursed and doesn't poison cache",
			localChain:        1,
			remoteChain:       2,
			expectedErrorRes:  true,
			expectedSecondRes: false,
			secondResult:      []protocol.Bytes16{},
		},
		{
			name:              "reader error then positive curse, cache doesn't poison, returns actual",
			localChain:        1,
			remoteChain:       3,
			expectedErrorRes:  true,
			expectedSecondRes: true,
			secondResult:      []protocol.Bytes16{GlobalCurseSubject},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			lggr, err := logger.New()
			assert.NoError(t, err)

			mockReader := common.NewMockRMNRemoteReader(t)

			// 1st call: reader returns error
			readerErr := errors.New("RPC error")
			mockReader.EXPECT().
				GetRMNCursedSubjects(mock.Anything).
				Return(nil, readerErr).
				Once()

			// 2nd call: returns the actual dataset
			mockReader.EXPECT().
				GetRMNCursedSubjects(mock.Anything).
				Return(tt.secondResult, nil).
				Once()

			checker := NewCachedCurseChecker(Params{
				Lggr: lggr,
				RmnReaders: map[protocol.ChainSelector]common.RMNRemoteReader{
					tt.localChain: mockReader,
				},
				CacheExpiry: 1 * time.Second,
			})

			// First call should assume cursed since the reader errors,
			// and must not populate the cache, so another underlying call will happen next time.
			res1 := checker.IsRemoteChainCursed(ctx, tt.localChain, tt.remoteChain)
			assert.Equal(t, tt.expectedErrorRes, res1, "should return expected result on reader error")

			// Now, the next call to IsRemoteChainCursed should trigger a new call to the reader,
			// since error results were not cached.
			res2 := checker.IsRemoteChainCursed(ctx, tt.localChain, tt.remoteChain)
			assert.Equal(t, tt.expectedSecondRes, res2, "should return actual result and not cache error")
		})
	}
}

func TestCachedCurseChecker_MultipleChains(t *testing.T) {
	tests := []struct {
		name         string
		cacheExpiry  time.Duration
		chains       []protocol.ChainSelector
		curseResults map[protocol.ChainSelector][]protocol.Bytes16
		checks       []struct {
			localChain     protocol.ChainSelector
			remoteChain    protocol.ChainSelector
			expectedResult bool
		}
	}{
		{
			name:        "multiple chains - independent caches",
			cacheExpiry: 1 * time.Second,
			chains:      []protocol.ChainSelector{1, 2, 3},
			curseResults: map[protocol.ChainSelector][]protocol.Bytes16{
				1: {ChainSelectorToBytes16(2)},
				2: {},
				3: {GlobalCurseSubject},
			},
			checks: []struct {
				localChain     protocol.ChainSelector
				remoteChain    protocol.ChainSelector
				expectedResult bool
			}{
				{localChain: 1, remoteChain: 2, expectedResult: true},  // Chain 1 has 2 cursed
				{localChain: 1, remoteChain: 3, expectedResult: false}, // Chain 1 doesn't have 3 cursed
				{localChain: 2, remoteChain: 1, expectedResult: false}, // Chain 2 has no curses
				{localChain: 3, remoteChain: 1, expectedResult: true},  // Chain 3 has global curse
				{localChain: 3, remoteChain: 2, expectedResult: true},  // Chain 3 has global curse
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			lggr, err := logger.New()
			assert.NoError(t, err)

			// Create mock readers for each chain
			mockReaders := make(map[protocol.ChainSelector]common.RMNRemoteReader)
			for _, chain := range tt.chains {
				mockReader := common.NewMockRMNRemoteReader(t)
				mockReader.EXPECT().
					GetRMNCursedSubjects(mock.Anything).
					Return(tt.curseResults[chain], nil).
					Once()
				mockReaders[chain] = mockReader
			}

			// Create cached curse checker
			checker := NewCachedCurseChecker(Params{
				Lggr:        lggr,
				RmnReaders:  mockReaders,
				CacheExpiry: tt.cacheExpiry,
			})

			// Perform all checks
			for _, check := range tt.checks {
				result := checker.IsRemoteChainCursed(ctx, check.localChain, check.remoteChain)
				assert.Equal(t, check.expectedResult, result,
					"unexpected result for localChain=%d, remoteChain=%d", check.localChain, check.remoteChain)
			}

			// Call again to verify cache is being used
			for _, check := range tt.checks {
				result := checker.IsRemoteChainCursed(ctx, check.localChain, check.remoteChain)
				assert.Equal(t, check.expectedResult, result,
					"unexpected cached result for localChain=%d, remoteChain=%d", check.localChain, check.remoteChain)
			}

			// Mock assertions will verify GetRMNCursedSubjects was only called once per chain
		})
	}
}

func TestCachedCurseChecker_GlobalCurseDetection(t *testing.T) {
	tests := []struct {
		name            string
		localChain      protocol.ChainSelector
		cursedSubjects  []protocol.Bytes16
		checkChains     []protocol.ChainSelector
		expectedResults []bool
	}{
		{
			name:            "global curse affects all chains",
			localChain:      1,
			cursedSubjects:  []protocol.Bytes16{GlobalCurseSubject},
			checkChains:     []protocol.ChainSelector{2, 3, 4, 5},
			expectedResults: []bool{true, true, true, true},
		},
		{
			name:            "specific chain curse only affects that chain",
			localChain:      1,
			cursedSubjects:  []protocol.Bytes16{ChainSelectorToBytes16(2)},
			checkChains:     []protocol.ChainSelector{2, 3, 4},
			expectedResults: []bool{true, false, false},
		},
		{
			name:       "multiple specific curses",
			localChain: 1,
			cursedSubjects: []protocol.Bytes16{
				ChainSelectorToBytes16(2),
				ChainSelectorToBytes16(4),
			},
			checkChains:     []protocol.ChainSelector{2, 3, 4, 5},
			expectedResults: []bool{true, false, true, false},
		},
		{
			name:       "global curse with specific chain curses",
			localChain: 1,
			cursedSubjects: []protocol.Bytes16{
				GlobalCurseSubject,
				ChainSelectorToBytes16(2),
			},
			checkChains:     []protocol.ChainSelector{2, 3, 4},
			expectedResults: []bool{true, true, true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			lggr, err := logger.New()
			assert.NoError(t, err)

			// Create mock reader
			mockReader := common.NewMockRMNRemoteReader(t)
			mockReader.EXPECT().
				GetRMNCursedSubjects(mock.Anything).
				Return(tt.cursedSubjects, nil).
				Once()

			// Create cached curse checker
			checker := NewCachedCurseChecker(Params{
				Lggr: lggr,
				RmnReaders: map[protocol.ChainSelector]common.RMNRemoteReader{
					tt.localChain: mockReader,
				},
				CacheExpiry: 1 * time.Second,
			})

			// Check each chain
			for i, remoteChain := range tt.checkChains {
				result := checker.IsRemoteChainCursed(ctx, tt.localChain, remoteChain)
				assert.Equal(t, tt.expectedResults[i], result,
					"unexpected result for remoteChain=%d", remoteChain)
			}

			// Mock assertions will verify GetRMNCursedSubjects was only called once
		})
	}
}

func TestCachedCurseChecker_NilCursedSubjects(t *testing.T) {
	tests := []struct {
		name           string
		localChain     protocol.ChainSelector
		remoteChain    protocol.ChainSelector
		expectedResult bool
	}{
		{
			name:           "nil cursed subjects treated as no curses",
			localChain:     1,
			remoteChain:    2,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			lggr, err := logger.New()
			assert.NoError(t, err)

			// Create mock reader
			mockReader := common.NewMockRMNRemoteReader(t)
			mockReader.EXPECT().
				GetRMNCursedSubjects(mock.Anything).
				Return(nil, nil).
				Once()

			// Create cached curse checker
			checker := NewCachedCurseChecker(Params{
				Lggr: lggr,
				RmnReaders: map[protocol.ChainSelector]common.RMNRemoteReader{
					tt.localChain: mockReader,
				},
				CacheExpiry: 1 * time.Second,
			})

			// Call should return false (no curses)
			result := checker.IsRemoteChainCursed(ctx, tt.localChain, tt.remoteChain)
			assert.Equal(t, tt.expectedResult, result)

			// Call again to verify cache works with nil results
			result2 := checker.IsRemoteChainCursed(ctx, tt.localChain, tt.remoteChain)
			assert.Equal(t, tt.expectedResult, result2)

			// Mock assertions will verify GetRMNCursedSubjects was only called once
		})
	}
}

func TestIsChainSelectorCursed(t *testing.T) {
	tests := []struct {
		name           string
		cursedSubjects cacheValue
		remoteChain    protocol.ChainSelector
		expectedResult bool
	}{
		{
			name: "global curse returns true",
			cursedSubjects: cacheValue{
				GlobalCurseSubject: struct{}{},
			},
			remoteChain:    42,
			expectedResult: true,
		},
		{
			name: "specific chain cursed returns true",
			cursedSubjects: cacheValue{
				ChainSelectorToBytes16(42): struct{}{},
			},
			remoteChain:    42,
			expectedResult: true,
		},
		{
			name: "different chain cursed returns false",
			cursedSubjects: cacheValue{
				ChainSelectorToBytes16(100): struct{}{},
			},
			remoteChain:    42,
			expectedResult: false,
		},
		{
			name:           "empty curse set returns false",
			cursedSubjects: cacheValue{},
			remoteChain:    42,
			expectedResult: false,
		},
		{
			name:           "nil curse set returns false",
			cursedSubjects: nil,
			remoteChain:    42,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isChainSelectorCursed(tt.cursedSubjects, tt.remoteChain)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
