package verifier

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

const testSelector = protocol.ChainSelector(5009297550715157269)

// setterAccessor is an Accessor that takes a data source. The embedded nil interface panics if
// any method other than the two defined here is called, which keeps the stub honest.
type setterAccessor struct {
	chainaccess.Accessor
	gotDataSource sqlutil.DataSource
	setCalls      int
	setErr        error
	closeCalls    int
}

func (s *setterAccessor) SetDataSource(_ context.Context, ds sqlutil.DataSource) error {
	s.setCalls++
	s.gotDataSource = ds
	return s.setErr
}

func (s *setterAccessor) Close() error {
	s.closeCalls++
	return nil
}

type stubRegistry struct{ accessor chainaccess.Accessor }

func (s stubRegistry) GetAccessor(context.Context, protocol.ChainSelector) (chainaccess.Accessor, error) {
	return s.accessor, nil
}

// A nil pool must still reach the accessor: only it knows whether its chain needs a database, so
// short-circuiting here would turn a misconfigured chain into a silently poller-less one.
func TestDataSourceRegistryInjectsEvenWhenPoolIsNil(t *testing.T) {
	t.Parallel()

	accessor := &setterAccessor{}
	r := newDataSourceRegistry(logger.Test(t), stubRegistry{accessor}, nil)

	got, err := r.GetAccessor(context.Background(), testSelector)
	require.NoError(t, err)
	require.Same(t, accessor, got)
	require.Equal(t, 1, accessor.setCalls)
	require.Nil(t, accessor.gotDataSource)
}

func TestDataSourceRegistryClosesAccessorWhenInjectionFails(t *testing.T) {
	t.Parallel()

	accessor := &setterAccessor{setErr: errors.New("poller start failed")}
	r := newDataSourceRegistry(logger.Test(t), stubRegistry{accessor}, nil)

	got, err := r.GetAccessor(context.Background(), testSelector)
	require.Nil(t, got)
	require.ErrorContains(t, err, "poller start failed")
	require.Equal(t, 1, accessor.closeCalls)
}

// Chain families with no database-backed services do not implement the setter, and must pass
// through untouched rather than being treated as a failure.
func TestDataSourceRegistryPassesThroughNonSetters(t *testing.T) {
	t.Parallel()

	accessor := mocks.NewMockAccessor(t)
	r := newDataSourceRegistry(logger.Test(t), stubRegistry{accessor}, nil)

	got, err := r.GetAccessor(context.Background(), testSelector)
	require.NoError(t, err)
	require.Same(t, accessor, got)
}
