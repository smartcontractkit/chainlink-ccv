package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDurationOrDefault(t *testing.T) {
	t.Parallel()

	t.Run("absent value returns the default", func(t *testing.T) {
		t.Parallel()

		got, err := ParseDurationOrDefault(nil, 3*time.Second)
		require.NoError(t, err)
		assert.Equal(t, 3*time.Second, got)
	})

	t.Run("quoted duration is parsed", func(t *testing.T) {
		t.Parallel()

		got, err := ParseDurationOrDefault("1h30m", time.Second)
		require.NoError(t, err)
		assert.Equal(t, 90*time.Minute, got)
	})

	t.Run("unparseable string is an error", func(t *testing.T) {
		t.Parallel()

		_, err := ParseDurationOrDefault("not-a-duration", time.Second)
		require.ErrorContains(t, err, "invalid duration format")
	})

	// Regression: deploy configs set attestation_api_timeout = 3000000000, which
	// TOML decodes as int64. This used to fall back to the 1s default silently.
	t.Run("bare TOML integer is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := ParseDurationOrDefault(int64(3000000000), time.Second)
		require.ErrorContains(t, err, "must be a quoted string")
	})

	t.Run("other non-string types are rejected", func(t *testing.T) {
		t.Parallel()

		for _, val := range []any{3000, 3.5, true, []any{"3s"}, map[string]any{"d": "3s"}} {
			_, err := ParseDurationOrDefault(val, time.Second)
			require.ErrorContainsf(t, err, "must be a quoted string", "value %v (%T)", val, val)
		}
	})

	t.Run("error names the offending value and type", func(t *testing.T) {
		t.Parallel()

		_, err := ParseDurationOrDefault(int64(3000000000), time.Second)
		require.ErrorContains(t, err, "int64")
		require.ErrorContains(t, err, "3000000000")
	})
}

func TestUnknownKeys(t *testing.T) {
	t.Parallel()

	allowed := []string{"known", "also_known"}

	t.Run("returns unknown keys sorted", func(t *testing.T) {
		t.Parallel()

		got := UnknownKeys(map[string]any{"zzz": 1, "known": 2, "aaa": 3, "also_known": 4}, allowed)
		assert.Equal(t, []string{"aaa", "zzz"}, got)
	})

	t.Run("returns nil when every key is allowed", func(t *testing.T) {
		t.Parallel()

		assert.Empty(t, UnknownKeys(map[string]any{"known": 1}, allowed))
	})

	t.Run("returns nil for an empty map", func(t *testing.T) {
		t.Parallel()

		assert.Empty(t, UnknownKeys(map[string]any{}, allowed))
	})
}

func TestParseIntOrDefault(t *testing.T) {
	t.Parallel()

	t.Run("absent value returns the default", func(t *testing.T) {
		t.Parallel()

		got, err := ParseIntOrDefault(nil, 20)
		require.NoError(t, err)
		assert.Equal(t, 20, got)
	})

	t.Run("integer types are accepted", func(t *testing.T) {
		t.Parallel()

		for _, val := range []any{int(7), int32(7), int64(7), uint32(7), uint64(7)} {
			got, err := ParseIntOrDefault(val, 20)
			require.NoErrorf(t, err, "value %v (%T)", val, val)
			assert.Equal(t, 7, got)
		}
	})

	t.Run("quoted integer is accepted", func(t *testing.T) {
		t.Parallel()

		got, err := ParseIntOrDefault("42", 20)
		require.NoError(t, err)
		assert.Equal(t, 42, got)
	})

	t.Run("unparseable string is an error", func(t *testing.T) {
		t.Parallel()

		_, err := ParseIntOrDefault("forty-two", 20)
		require.ErrorContains(t, err, "invalid integer format")
	})

	t.Run("unsupported types are rejected", func(t *testing.T) {
		t.Parallel()

		for _, val := range []any{true, 2.5, []any{1}, map[string]any{"n": 1}} {
			_, err := ParseIntOrDefault(val, 20)
			require.ErrorContainsf(t, err, "must be a TOML integer", "value %v (%T)", val, val)
		}
	})
}
