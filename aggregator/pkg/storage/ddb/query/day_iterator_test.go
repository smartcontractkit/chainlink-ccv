package query

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDayIterator(t *testing.T) {
	// Use a minimum date that's before all test dates
	testMinDate := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		start    int64
		end      int64
		expected []string
	}{
		{
			name:     "single day",
			start:    time.Date(2023, 10, 15, 14, 30, 0, 0, time.UTC).Unix(),
			end:      time.Date(2023, 10, 15, 16, 45, 0, 0, time.UTC).Unix(),
			expected: []string{"2023-10-15"},
		},
		{
			name:     "multiple days",
			start:    time.Date(2023, 10, 15, 14, 30, 0, 0, time.UTC).Unix(),
			end:      time.Date(2023, 10, 17, 16, 45, 0, 0, time.UTC).Unix(),
			expected: []string{"2023-10-15", "2023-10-16", "2023-10-17"},
		},
		{
			name:     "cross month boundary",
			start:    time.Date(2023, 9, 30, 14, 30, 0, 0, time.UTC).Unix(),
			end:      time.Date(2023, 10, 2, 16, 45, 0, 0, time.UTC).Unix(),
			expected: []string{"2023-09-30", "2023-10-01", "2023-10-02"},
		},
		{
			name:     "cross year boundary",
			start:    time.Date(2023, 12, 30, 14, 30, 0, 0, time.UTC).Unix(),
			end:      time.Date(2024, 1, 2, 16, 45, 0, 0, time.UTC).Unix(),
			expected: []string{"2023-12-30", "2023-12-31", "2024-01-01", "2024-01-02"},
		},
		{
			name:     "same timestamp (same day)",
			start:    time.Date(2023, 10, 15, 14, 30, 0, 0, time.UTC).Unix(),
			end:      time.Date(2023, 10, 15, 14, 30, 0, 0, time.UTC).Unix(),
			expected: []string{"2023-10-15"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iterator := NewDayIterator(tt.start, tt.end, testMinDate, nil)
			var result []string

			for iterator.Next() {
				result = append(result, iterator.Day())
				iterator.Advance()
			}

			require.Equal(t, tt.expected, result)
		})
	}
}

func TestDayIteratorBehavior(t *testing.T) {
	// Use a minimum date that's before all test dates
	testMinDate := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("iterator exhaustion", func(t *testing.T) {
		start := time.Date(2023, 10, 15, 14, 30, 0, 0, time.UTC).Unix()
		end := time.Date(2023, 10, 16, 16, 45, 0, 0, time.UTC).Unix()

		iterator := NewDayIterator(start, end, testMinDate, nil)

		// First iteration
		require.True(t, iterator.Next())
		require.Equal(t, "2023-10-15", iterator.Day())
		iterator.Advance()

		// Second iteration
		require.True(t, iterator.Next())
		require.Equal(t, "2023-10-16", iterator.Day())
		iterator.Advance()

		// Should be exhausted now
		require.False(t, iterator.Next())
		require.False(t, iterator.Next()) // Multiple calls should be safe
	})

	t.Run("multiple calls to Day() without Advance()", func(t *testing.T) {
		start := time.Date(2023, 10, 15, 14, 30, 0, 0, time.UTC).Unix()
		end := time.Date(2023, 10, 15, 16, 45, 0, 0, time.UTC).Unix()

		iterator := NewDayIterator(start, end, testMinDate, nil)
		require.True(t, iterator.Next())

		// Multiple calls should return the same value
		require.Equal(t, "2023-10-15", iterator.Day())
		require.Equal(t, "2023-10-15", iterator.Day())
		require.Equal(t, "2023-10-15", iterator.Day())
	})

	t.Run("start with pagination token on day after start", func(t *testing.T) {
		start := time.Date(2023, 10, 15, 14, 30, 0, 0, time.UTC).Unix()
		end := time.Date(2023, 10, 19, 16, 45, 0, 0, time.UTC).Unix()

		paginationToken := &AggregatedReportPaginationToken{
			LastDay: "2023-10-18",
		}

		iterator := NewDayIterator(start, end, testMinDate, paginationToken)

		// Should start at the token day
		require.True(t, iterator.Next())
		require.Equal(t, "2023-10-18", iterator.Day())
		iterator.Advance()

		require.True(t, iterator.Next())
		require.Equal(t, "2023-10-19", iterator.Day())
		iterator.Advance()

		require.False(t, iterator.Next()) // Exhausted
	})
}
