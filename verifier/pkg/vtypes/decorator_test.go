package vtypes

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type namedVerifier struct {
	Verifier // inner, nil for the base
	name     string
}

func (n namedVerifier) VerifyMessages(context.Context, []VerificationTask) []VerificationResult {
	return nil
}

func namedDecorator(name string) VerifierDecorator {
	return func(inner Verifier) (Verifier, error) {
		return namedVerifier{Verifier: inner, name: name}, nil
	}
}

func TestChain(t *testing.T) {
	inner := namedVerifier{name: "inner"}

	t.Run("no decorators returns inner unchanged", func(t *testing.T) {
		got, err := Chain(inner)
		require.NoError(t, err)
		assert.Equal(t, inner, got)
	})

	t.Run("first decorator listed is outermost", func(t *testing.T) {
		got, err := Chain(inner, namedDecorator("first"), namedDecorator("second"))
		require.NoError(t, err)

		outer, ok := got.(namedVerifier)
		require.True(t, ok)
		assert.Equal(t, "first", outer.name, "the first decorator sees every task first")
		middle, ok := outer.Verifier.(namedVerifier)
		require.True(t, ok)
		assert.Equal(t, "second", middle.name)
		assert.Equal(t, inner, middle.Verifier)
	})

	t.Run("nil decorators are skipped", func(t *testing.T) {
		got, err := Chain(inner, nil, namedDecorator("only"))
		require.NoError(t, err)
		outer, ok := got.(namedVerifier)
		require.True(t, ok)
		assert.Equal(t, "only", outer.name)
		assert.Equal(t, inner, outer.Verifier)
	})

	t.Run("a decorator error names its position", func(t *testing.T) {
		broken := func(Verifier) (Verifier, error) { return nil, errors.New("boom") }
		_, err := Chain(inner, namedDecorator("ok"), broken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decorator 1")
	})

	t.Run("a decorator returning nil is an error", func(t *testing.T) {
		_, err := Chain(inner, func(Verifier) (Verifier, error) { return nil, nil })
		require.Error(t, err)
	})

	t.Run("nil inner is an error", func(t *testing.T) {
		_, err := Chain(nil, namedDecorator("first"))
		require.Error(t, err)
	})
}
