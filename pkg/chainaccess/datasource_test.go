package chainaccess_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// persistentFactory accepts a data source, standing in for the EVM accessor factory.
type persistentFactory struct {
	got      sqlutil.DataSource
	setCalls int
}

func (f *persistentFactory) GetAccessor(context.Context, protocol.ChainSelector) (chainaccess.Accessor, error) {
	return nil, nil //nolint:nilnil // not exercised by these tests
}

func (f *persistentFactory) SetDataSource(ds sqlutil.DataSource) {
	f.got = ds
	f.setCalls++
}

// statelessFactory does not implement DataSourceSetter, standing in for the Solana and Canton
// accessor factories, which hold no durable state.
type statelessFactory struct{}

func (statelessFactory) GetAccessor(context.Context, protocol.ChainSelector) (chainaccess.Accessor, error) {
	return nil, nil //nolint:nilnil // not exercised by these tests
}

// fakeDataSource is a non-nil DataSource; none of its methods are called here.
type fakeDataSource struct {
	sqlutil.DataSource
}

func TestWithDataSourceReachesFactoriesThatWantIt(t *testing.T) {
	family := chainaccess.ChainFamily("test-datasource-setter")
	fac := &persistentFactory{}
	chainaccess.Register(family, func(logger.Logger, chainaccess.GenericConfig) (chainaccess.AccessorFactory, error) {
		return fac, nil
	})

	ds := fakeDataSource{}
	_, err := chainaccess.NewRegistry(logger.Test(t), "", chainaccess.WithDataSource(ds))
	require.NoError(t, err)

	require.Equal(t, 1, fac.setCalls, "the factory should be given the handle exactly once")
	require.Equal(t, ds, fac.got)
}

// TestWithoutDataSourceLeavesFactoryUnset covers the deployment that configures no database: the
// hook is not called at all, so a family can tell "no database" from "some database".
func TestWithoutDataSourceLeavesFactoryUnset(t *testing.T) {
	family := chainaccess.ChainFamily("test-datasource-absent")
	fac := &persistentFactory{}
	chainaccess.Register(family, func(logger.Logger, chainaccess.GenericConfig) (chainaccess.AccessorFactory, error) {
		return fac, nil
	})

	_, err := chainaccess.NewRegistry(logger.Test(t), "")
	require.NoError(t, err)

	require.Zero(t, fac.setCalls, "no data source means the hook is never called")
	require.Nil(t, fac.got)
}

// TestFactoryWithoutSetterIsUnaffected is the compatibility case that matters most: chain families
// live in their own repos and implement the constructor signature without knowing about this hook.
// Passing a data source must not disturb them.
func TestFactoryWithoutSetterIsUnaffected(t *testing.T) {
	family := chainaccess.ChainFamily("test-datasource-stateless")
	chainaccess.Register(family, func(logger.Logger, chainaccess.GenericConfig) (chainaccess.AccessorFactory, error) {
		return statelessFactory{}, nil
	})

	reg, err := chainaccess.NewRegistry(logger.Test(t), "", chainaccess.WithDataSource(fakeDataSource{}))
	require.NoError(t, err)
	require.NotNil(t, reg)
}
