package bootstrap

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type keystoreSettingAccessor struct {
	*mocks.MockAccessor
	setErr    error
	setCalls  int
	gotMarker string
	gotStore  keystore.Keystore
}

type stubKeystore struct {
	keystore.Keystore
}

type keystoreContextMarkerKey struct{}

func (a *keystoreSettingAccessor) SetKeystore(ctx context.Context, ks keystore.Keystore) error {
	a.setCalls++
	a.gotMarker, _ = ctx.Value(keystoreContextMarkerKey{}).(string)
	a.gotStore = ks
	return a.setErr
}

func TestKeystoreRegistryInjectsWithRequestContext(t *testing.T) {
	t.Parallel()

	const contextMarker = "context-marker"
	ctx := context.WithValue(context.Background(), keystoreContextMarkerKey{}, contextMarker)
	accessor := &keystoreSettingAccessor{MockAccessor: mocks.NewMockAccessor(t)}
	inner := mocks.NewMockAccessorFactory(t)
	inner.EXPECT().GetAccessor(mock.Anything, protocol.ChainSelector(42)).Return(accessor, nil).Once()
	ks := &stubKeystore{}

	registry := NewKeystoreRegistry(logger.Test(t), inner, ks)
	got, err := registry.GetAccessor(ctx, protocol.ChainSelector(42))
	require.NoError(t, err)
	require.Same(t, accessor, got)
	require.Equal(t, 1, accessor.setCalls)
	require.Equal(t, contextMarker, accessor.gotMarker)
	require.Same(t, ks, accessor.gotStore)
}

func TestKeystoreRegistryClosesAccessorWhenInjectionFails(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("txm failed to start")
	accessor := &keystoreSettingAccessor{
		MockAccessor: mocks.NewMockAccessor(t),
		setErr:       wantErr,
	}
	accessor.EXPECT().Close().Return(nil).Once()
	inner := mocks.NewMockAccessorFactory(t)
	inner.EXPECT().GetAccessor(mock.Anything, protocol.ChainSelector(42)).Return(accessor, nil).Once()

	registry := NewKeystoreRegistry(logger.Test(t), inner, &stubKeystore{})
	got, err := registry.GetAccessor(context.Background(), protocol.ChainSelector(42))
	require.Nil(t, got)
	require.ErrorIs(t, err, wantErr)
	require.ErrorContains(t, err, "failed to inject keystore for chain 42")
}

func TestKeystoreRegistrySkipsInjectionWhenKeystoreIsNil(t *testing.T) {
	t.Parallel()

	accessor := &keystoreSettingAccessor{MockAccessor: mocks.NewMockAccessor(t)}
	inner := mocks.NewMockAccessorFactory(t)
	inner.EXPECT().GetAccessor(mock.Anything, protocol.ChainSelector(42)).Return(accessor, nil).Once()

	registry := NewKeystoreRegistry(logger.Test(t), inner, nil)
	got, err := registry.GetAccessor(context.Background(), protocol.ChainSelector(42))
	require.NoError(t, err)
	require.Same(t, accessor, got)
	require.Zero(t, accessor.setCalls)
}
