package backofftimeprovider

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var defaultNtpServer = "time.google.com"

func TestBackoffNTPProvider_GetTime_Success(t *testing.T) {
	tests := []struct {
		name           string
		expectedTime   time.Time
		backoffDur     time.Duration
		expectedResult time.Time
	}{
		{
			name:           "successful NTP time retrieval",
			expectedTime:   time.Date(2025, 11, 25, 12, 0, 0, 0, time.UTC),
			backoffDur:     1 * time.Second,
			expectedResult: time.Date(2025, 11, 25, 12, 0, 0, 0, time.UTC),
		},
		{
			name:           "successful NTP with different time",
			expectedTime:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			backoffDur:     5 * time.Second,
			expectedResult: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			lggr := logger.Test(t)
			provider := NewBackoffNTPProvider(lggr, tt.backoffDur, defaultNtpServer)

			// Mock NTP to return expected time
			originalNtpTimeFunc := ntpTimeFunc
			defer func() { ntpTimeFunc = originalNtpTimeFunc }()
			ntpTimeFunc = func(host string) (time.Time, error) {
				return tt.expectedTime, nil
			}

			// Execute
			result := provider.GetTime()

			// Assert
			assert.Equal(t, tt.expectedResult, result)
			assert.Equal(t, 0, provider.failedAttempts)
			assert.True(t, provider.lastFailureTime.IsZero())
		})
	}
}

func TestBackoffNTPProvider_GetTime_FailureReturnsLocalTime(t *testing.T) {
	tests := []struct {
		name       string
		backoffDur time.Duration
		ntpError   error
	}{
		{
			name:       "NTP failure returns local time",
			backoffDur: 1 * time.Second,
			ntpError:   errors.New("connection timeout"),
		},
		{
			name:       "NTP failure with different error",
			backoffDur: 2 * time.Second,
			ntpError:   errors.New("server unreachable"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			lggr := logger.Test(t)
			provider := NewBackoffNTPProvider(lggr, tt.backoffDur, defaultNtpServer)

			// Mock NTP to fail
			originalNtpTimeFunc := ntpTimeFunc
			defer func() { ntpTimeFunc = originalNtpTimeFunc }()
			ntpTimeFunc = func(host string) (time.Time, error) {
				return time.Time{}, tt.ntpError
			}

			// Execute
			before := time.Now().UTC()
			result := provider.GetTime()
			after := time.Now().UTC()

			// Assert - result should be local time (between before and after)
			assert.True(t, result.After(before) || result.Equal(before))
			assert.True(t, result.Before(after) || result.Equal(after))
			assert.Equal(t, 1, provider.failedAttempts)
			assert.False(t, provider.lastFailureTime.IsZero())
		})
	}
}

func TestBackoffNTPProvider_GetTime_BackoffBehavior(t *testing.T) {
	tests := []struct {
		name                  string
		backoffDur            time.Duration
		initialFailedAttempts int
		setLastFailureTime    time.Time
		expectNTPCall         bool
	}{
		{
			name:                  "in backoff period - should not call NTP",
			backoffDur:            2 * time.Second,
			initialFailedAttempts: 1,
			setLastFailureTime:    time.Now().UTC().Add(-500 * time.Millisecond), // 500ms ago
			expectNTPCall:         false,
		},
		{
			name:                  "backoff expired - should call NTP",
			backoffDur:            1 * time.Second,
			initialFailedAttempts: 1,
			setLastFailureTime:    time.Now().UTC().Add(-2 * time.Second), // 2s ago
			expectNTPCall:         true,
		},
		{
			name:                  "multiple failures - still in backoff",
			backoffDur:            1 * time.Second,
			initialFailedAttempts: 2,
			setLastFailureTime:    time.Now().UTC().Add(-2 * time.Second), // 2s ago, but need 3s
			expectNTPCall:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			lggr := logger.Test(t)
			provider := NewBackoffNTPProvider(lggr, tt.backoffDur, defaultNtpServer)
			provider.failedAttempts = tt.initialFailedAttempts
			provider.lastFailureTime = tt.setLastFailureTime

			// Mock NTP
			ntpCalled := false
			originalNtpTimeFunc := ntpTimeFunc
			defer func() { ntpTimeFunc = originalNtpTimeFunc }()
			ntpTimeFunc = func(host string) (time.Time, error) {
				ntpCalled = true
				return time.Date(2025, 11, 25, 12, 0, 0, 0, time.UTC), nil
			}

			// Execute
			result := provider.GetTime()

			// Assert
			assert.Equal(t, tt.expectNTPCall, ntpCalled)
			assert.False(t, result.IsZero())

			if tt.expectNTPCall {
				// If NTP was called and succeeded, counters should be reset
				assert.Equal(t, 0, provider.failedAttempts)
			} else {
				// If in backoff, counters should remain unchanged
				assert.Equal(t, tt.initialFailedAttempts, provider.failedAttempts)
			}
		})
	}
}

func TestBackoffNTPProvider_GetTime_ExponentialBackoff(t *testing.T) {
	tests := []struct {
		name                 string
		backoffDur           time.Duration
		failedAttempts       int
		expectedBackoffMulti int // multiplier for backoff duration
	}{
		{
			name:                 "first failure - 1x backoff",
			backoffDur:           1 * time.Second,
			failedAttempts:       1,
			expectedBackoffMulti: 1,
		},
		{
			name:                 "second failure - 3x backoff",
			backoffDur:           1 * time.Second,
			failedAttempts:       2,
			expectedBackoffMulti: 3,
		},
		{
			name:                 "third failure - 6x backoff",
			backoffDur:           1 * time.Second,
			failedAttempts:       3,
			expectedBackoffMulti: 6,
		},
		{
			name:                 "fourth failure - 10x backoff",
			backoffDur:           1 * time.Second,
			failedAttempts:       4,
			expectedBackoffMulti: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			lggr := logger.Test(t)
			provider := NewBackoffNTPProvider(lggr, tt.backoffDur, defaultNtpServer)
			provider.failedAttempts = tt.failedAttempts

			// Execute
			result := provider.calculateBackoffDuration()

			// Assert
			expected := tt.backoffDur * time.Duration(tt.expectedBackoffMulti)
			assert.Equal(t, expected, result)
		})
	}
}

func TestBackoffNTPProvider_GetTime_MultipleFailuresThenSuccess(t *testing.T) {
	tests := []struct {
		name        string
		backoffDur  time.Duration
		numFailures int
		successTime time.Time
	}{
		{
			name:        "two failures then success",
			backoffDur:  50 * time.Millisecond,
			numFailures: 2,
			successTime: time.Date(2025, 11, 25, 12, 0, 0, 0, time.UTC),
		},
		{
			name:        "three failures then success",
			backoffDur:  50 * time.Millisecond,
			numFailures: 3,
			successTime: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			lggr := logger.Test(t)
			provider := NewBackoffNTPProvider(lggr, tt.backoffDur, defaultNtpServer)

			originalNtpTimeFunc := ntpTimeFunc
			defer func() { ntpTimeFunc = originalNtpTimeFunc }()

			callCount := 0
			ntpTimeFunc = func(host string) (time.Time, error) {
				callCount++
				if callCount <= tt.numFailures {
					return time.Time{}, errors.New("ntp failure")
				}
				return tt.successTime, nil
			}

			// Execute failures - need to wait for backoff between each attempt
			for i := 0; i < tt.numFailures; i++ {
				result := provider.GetTime()
				assert.False(t, result.IsZero())
				assert.Equal(t, i+1, provider.failedAttempts)

				// Wait for backoff to expire before next attempt
				if i < tt.numFailures-1 {
					backoffDur := provider.calculateBackoffDuration()
					time.Sleep(backoffDur + 10*time.Millisecond)
				}
			}

			// Wait for final backoff to expire
			backoffDur := provider.calculateBackoffDuration()
			time.Sleep(backoffDur + 10*time.Millisecond)

			// Execute success
			result := provider.GetTime()

			// Assert
			assert.Equal(t, tt.successTime, result)
			assert.Equal(t, 0, provider.failedAttempts)
			assert.True(t, provider.lastFailureTime.IsZero())
		})
	}
}

func TestBackoffNTPProvider_GetTime_ConcurrentCalls(t *testing.T) {
	tests := []struct {
		name          string
		backoffDur    time.Duration
		numGoroutines int
		callsPerGo    int
	}{
		{
			name:          "concurrent calls - 10 goroutines",
			backoffDur:    1 * time.Second,
			numGoroutines: 10,
			callsPerGo:    5,
		},
		{
			name:          "concurrent calls - 50 goroutines",
			backoffDur:    500 * time.Millisecond,
			numGoroutines: 50,
			callsPerGo:    3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			lggr := logger.Test(t)
			provider := NewBackoffNTPProvider(lggr, tt.backoffDur, defaultNtpServer)

			// Mock NTP to always succeed
			originalNtpTimeFunc := ntpTimeFunc
			defer func() { ntpTimeFunc = originalNtpTimeFunc }()
			expectedTime := time.Date(2025, 11, 25, 12, 0, 0, 0, time.UTC)
			ntpTimeFunc = func(host string) (time.Time, error) {
				return expectedTime, nil
			}

			// Execute concurrent calls
			var wg sync.WaitGroup
			results := make([]time.Time, tt.numGoroutines*tt.callsPerGo)
			resultIdx := 0
			var mu sync.Mutex

			for i := 0; i < tt.numGoroutines; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := 0; j < tt.callsPerGo; j++ {
						result := provider.GetTime()
						mu.Lock()
						results[resultIdx] = result
						resultIdx++
						mu.Unlock()
					}
				}()
			}

			wg.Wait()

			// Assert - all results should be valid times
			for _, result := range results {
				assert.False(t, result.IsZero())
			}
		})
	}
}

func TestBackoffNTPProvider_GetTime_BackoffDuringConcurrentCalls(t *testing.T) {
	tests := []struct {
		name          string
		backoffDur    time.Duration
		numGoroutines int
	}{
		{
			name:          "backoff with concurrent calls",
			backoffDur:    100 * time.Millisecond,
			numGoroutines: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			lggr := logger.Test(t)
			provider := NewBackoffNTPProvider(lggr, tt.backoffDur, defaultNtpServer)

			// Mock NTP to fail initially
			originalNtpTimeFunc := ntpTimeFunc
			defer func() { ntpTimeFunc = originalNtpTimeFunc }()

			var ntpCallCount int
			var ntpMu sync.Mutex

			ntpTimeFunc = func(host string) (time.Time, error) {
				ntpMu.Lock()
				ntpCallCount++
				ntpMu.Unlock()
				return time.Time{}, errors.New("ntp failure")
			}

			// First call to trigger backoff
			result := provider.GetTime()
			require.False(t, result.IsZero())
			require.Equal(t, 1, provider.failedAttempts)

			initialCallCount := ntpCallCount

			// Execute concurrent calls while in backoff
			var wg sync.WaitGroup
			results := make([]time.Time, tt.numGoroutines)

			for i := 0; i < tt.numGoroutines; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					results[idx] = provider.GetTime()
				}(i)
			}

			wg.Wait()

			// Assert - all results should be valid, but NTP should not have been called again
			for _, result := range results {
				assert.False(t, result.IsZero())
			}

			// NTP should not have been called during backoff period
			assert.Equal(t, initialCallCount, ntpCallCount, "NTP should not be called while in backoff")
			assert.Equal(t, 1, provider.failedAttempts, "failed attempts should not increase during backoff")
		})
	}
}

func TestBackoffNTPProvider_GetTime_FailureUsesCachedDifference(t *testing.T) {
	tests := []struct {
		name           string
		backoffDur     time.Duration
		offsetDuration time.Duration // difference between NTP and Local
	}{
		{
			name:           "NTP 1 hour ahead",
			backoffDur:     1 * time.Second,
			offsetDuration: 1 * time.Hour,
		},
		{
			name:           "NTP 1 hour behind",
			backoffDur:     1 * time.Second,
			offsetDuration: -1 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			lggr := logger.Test(t)
			provider := NewBackoffNTPProvider(lggr, tt.backoffDur, defaultNtpServer)

			originalNtpTimeFunc := ntpTimeFunc
			defer func() { ntpTimeFunc = originalNtpTimeFunc }()

			// 1. Success call
			ntpTimeFunc = func(host string) (time.Time, error) {
				return time.Now().UTC().Add(tt.offsetDuration), nil
			}

			successResult := provider.GetTime()
			// Assert it's close to expected offset
			now := time.Now().UTC()
			assert.InDelta(t, float64(now.Add(tt.offsetDuration).Unix()), float64(successResult.Unix()), 1.0)
			assert.Equal(t, 0, provider.failedAttempts)
			assert.False(t, provider.lastSuccessLocalTime.IsZero())
			assert.False(t, provider.lastSuccessNTPTime.IsZero())

			// 2. Failure call
			ntpTimeFunc = func(host string) (time.Time, error) {
				return time.Time{}, errors.New("ntp failure")
			}

			failureResult := provider.GetTime()
			now2 := time.Now().UTC()

			// Assert
			// failureResult should be approximately now2 + offsetDuration
			expectedFailureResult := now2.Add(tt.offsetDuration)
			assert.InDelta(t, float64(expectedFailureResult.Unix()), float64(failureResult.Unix()), 1.0)
			assert.Equal(t, 1, provider.failedAttempts)
		})
	}
}

func TestNewBackoffNTPProvider(t *testing.T) {
	tests := []struct {
		name       string
		backoffDur time.Duration
	}{
		{
			name:       "create with 1 second backoff",
			backoffDur: 1 * time.Second,
		},
		{
			name:       "create with 5 second backoff",
			backoffDur: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			lggr := logger.Test(t)

			// Execute
			provider := NewBackoffNTPProvider(lggr, tt.backoffDur, defaultNtpServer)

			// Assert
			assert.NotNil(t, provider)
			assert.Equal(t, tt.backoffDur, provider.backoffDuration)
			assert.Equal(t, 0, provider.failedAttempts)
			assert.True(t, provider.lastFailureTime.IsZero())
		})
	}
}
