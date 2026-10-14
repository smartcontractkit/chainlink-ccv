package constructors

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
)

type stubFilterLoader struct {
	filters map[string]logpoller.Filter
	err     error
}

func (s stubFilterLoader) LoadFilters(context.Context) (map[string]logpoller.Filter, error) {
	return s.filters, s.err
}

func TestFilterRegistered(t *testing.T) {
	const name = "ccv-verifier - verifier-1:0x00000000000000000000000000000000000000aA"
	stored := stubFilterLoader{filters: map[string]logpoller.Filter{name: {Name: name}}}

	got, err := filterRegistered(t.Context(), stored, name)
	require.NoError(t, err)
	require.True(t, got)

	got, err = filterRegistered(t.Context(), stored, "ccv-verifier - verifier-2:0x00000000000000000000000000000000000000aA")
	require.NoError(t, err)
	require.False(t, got)

	_, err = filterRegistered(t.Context(), stubFilterLoader{err: errors.New("db down")}, name)
	require.ErrorContains(t, err, "db down")
}
