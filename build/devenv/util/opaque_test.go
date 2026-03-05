package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// input is a concrete struct with TOML tags used for round-trip tests.
type input struct {
	Field1         string `toml:"field1"`
	SomeOtherField string `toml:"some_other_field"`
}

// nestedInput has a nested struct to exercise more of the TOML encode/decode path.
type nestedInput struct {
	Name   string `toml:"name"`
	Inner  inner  `toml:"inner"`
	Number int    `toml:"number"`
}

type inner struct {
	Value string `toml:"value"`
}

func TestConcreteToOpaqueRoundTrip(t *testing.T) {
	t.Run("concrete to opaque to concrete returns same struct", func(t *testing.T) {
		original := input{
			Field1:         "hello",
			SomeOtherField: "world",
		}
		opaque, err := ConcreteToOpaque(original)
		require.NoError(t, err)
		require.NotNil(t, opaque)

		decoded, err := OpaqueToConcreteStrict[input](opaque)
		require.NoError(t, err)
		require.NotNil(t, decoded)
		require.Equal(t, original, *decoded)
	})

	t.Run("round trip with nested struct", func(t *testing.T) {
		original := nestedInput{
			Name:   "outer",
			Number: 42,
			Inner:  inner{Value: "nested"},
		}
		opaque, err := ConcreteToOpaque(original)
		require.NoError(t, err)
		require.NotNil(t, opaque)

		decoded, err := OpaqueToConcreteStrict[nestedInput](opaque)
		require.NoError(t, err)
		require.NotNil(t, decoded)
		require.Equal(t, original, *decoded)
	})

	t.Run("round trip with zero value struct", func(t *testing.T) {
		var original input
		opaque, err := ConcreteToOpaque(original)
		require.NoError(t, err)
		require.NotNil(t, opaque)

		decoded, err := OpaqueToConcreteStrict[input](opaque)
		require.NoError(t, err)
		require.NotNil(t, decoded)
		require.Equal(t, original, *decoded)
	})
}

// TestOpaqueToConcreteRoundTrip asserts that OpaqueToConcreteStrict -> ConcreteToOpaque
// yields an OpaqueConfig equal to the original, i.e. no loss or distortion when
// decoding then re-encoding.
func TestOpaqueToConcreteRoundTrip(t *testing.T) {
	t.Run("opaque to concrete to opaque returns same opaque config", func(t *testing.T) {
		original := input{
			Field1:         "hello",
			SomeOtherField: "world",
		}
		opaque1, err := ConcreteToOpaque(original)
		require.NoError(t, err)
		require.NotNil(t, opaque1)

		decoded, err := OpaqueToConcreteStrict[input](opaque1)
		require.NoError(t, err)
		require.NotNil(t, decoded)

		opaque2, err := ConcreteToOpaque(*decoded)
		require.NoError(t, err)
		require.Equal(t, opaque1, opaque2)
	})

	t.Run("opaque to concrete to opaque with nested struct", func(t *testing.T) {
		original := nestedInput{
			Name:   "outer",
			Number: 42,
			Inner:  inner{Value: "nested"},
		}
		opaque1, err := ConcreteToOpaque(original)
		require.NoError(t, err)
		require.NotNil(t, opaque1)

		decoded, err := OpaqueToConcreteStrict[nestedInput](opaque1)
		require.NoError(t, err)
		require.NotNil(t, decoded)

		opaque2, err := ConcreteToOpaque(*decoded)
		require.NoError(t, err)
		require.Equal(t, opaque1, opaque2)
	})
}

func TestOpaqueToConcreteStrict_UndecodedKeys(t *testing.T) {
	// Opaque config with an extra key that does not exist on input.
	opaque := OpaqueConfig{
		"field1":           "ok",
		"some_other_field": "ok",
		"unknown_key":      "should fail",
	}
	_, err := OpaqueToConcreteStrict[input](opaque)
	require.Error(t, err)
	require.Contains(t, err.Error(), "undecoded keys")
	require.Contains(t, err.Error(), "unknown_key")
}

func TestConcreteToOpaque(t *testing.T) {
	t.Run("encodes struct to opaque map with toml key names", func(t *testing.T) {
		original := input{
			Field1:         "a",
			SomeOtherField: "b",
		}
		opaque, err := ConcreteToOpaque(original)
		require.NoError(t, err)
		require.Equal(t, "a", opaque["field1"])
		require.Equal(t, "b", opaque["some_other_field"])
	})
}
