package verifier

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type initialDisabledStatusManager struct {
	statuses map[protocol.ChainSelector]*protocol.ChainStatusInfo
	readErr  error
	writeErr error
	writes   [][]protocol.ChainStatusInfo
}

func (m *initialDisabledStatusManager) ReadChainStatuses(_ context.Context, _ []protocol.ChainSelector) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
	return m.statuses, m.readErr
}

func (m *initialDisabledStatusManager) WriteChainStatuses(_ context.Context, statuses []protocol.ChainStatusInfo) error {
	m.writes = append(m.writes, statuses)
	if m.writeErr != nil {
		return m.writeErr
	}
	if m.statuses == nil {
		m.statuses = make(map[protocol.ChainSelector]*protocol.ChainStatusInfo)
	}
	for _, status := range statuses {
		m.statuses[status.ChainSelector] = &status
	}
	return nil
}

func initialDisabledCoordinatorConfig(selectors ...protocol.ChainSelector) CoordinatorConfig {
	configured := make(map[protocol.ChainSelector]vtypes.SourceConfig)
	for _, selector := range selectors {
		configured[selector] = vtypes.SourceConfig{}
	}
	return CoordinatorConfig{
		SourceConfigs:                 configured,
		InitialDisabledChainSelectors: selectors,
	}
}

func TestFilterConfiguredSourceReaders_SeedsInitialDisabledChains(t *testing.T) {
	const chain protocol.ChainSelector = 1456215246176062136
	manager := &initialDisabledStatusManager{statuses: map[protocol.ChainSelector]*protocol.ChainStatusInfo{}}
	readers := map[protocol.ChainSelector]chainaccess.SourceReader{chain: mocks.NewMockSourceReader(t)}

	configured, err := filterConfiguredSourceReaders(t.Context(), logger.Test(t), initialDisabledCoordinatorConfig(chain), readers, manager)
	require.NoError(t, err)
	require.Len(t, configured, 1)
	require.Len(t, manager.writes, 1)
	require.Len(t, manager.writes[0], 1)
	status := manager.writes[0][0]
	require.Equal(t, chain, status.ChainSelector)
	require.True(t, status.Disabled)
	require.Equal(t, 0, status.FinalizedBlockHeight.Sign())
	require.True(t, manager.statuses[chain].Disabled)
}

func TestFilterConfiguredSourceReaders_PreservesExistingDisabledState(t *testing.T) {
	const chain protocol.ChainSelector = 1
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicitly enabled", true: "still disabled"}[disabled], func(t *testing.T) {
			manager := &initialDisabledStatusManager{statuses: map[protocol.ChainSelector]*protocol.ChainStatusInfo{
				chain: {ChainSelector: chain, FinalizedBlockHeight: big.NewInt(123), Disabled: disabled},
			}}
			readers := map[protocol.ChainSelector]chainaccess.SourceReader{chain: mocks.NewMockSourceReader(t)}

			_, err := filterConfiguredSourceReaders(t.Context(), logger.Test(t), initialDisabledCoordinatorConfig(chain), readers, manager)
			require.NoError(t, err)
			require.Empty(t, manager.writes, "an existing operator-controlled row must not be overwritten")
			require.Equal(t, disabled, manager.statuses[chain].Disabled)
			require.Equal(t, int64(123), manager.statuses[chain].FinalizedBlockHeight.Int64())
		})
	}
}

func TestFilterConfiguredSourceReaders_InitialDisabledFailuresFailClosed(t *testing.T) {
	const chain protocol.ChainSelector = 1
	readers := func() map[protocol.ChainSelector]chainaccess.SourceReader {
		return map[protocol.ChainSelector]chainaccess.SourceReader{chain: mocks.NewMockSourceReader(t)}
	}

	t.Run("read failure", func(t *testing.T) {
		manager := &initialDisabledStatusManager{readErr: errors.New("read failed")}
		_, err := filterConfiguredSourceReaders(t.Context(), logger.Test(t), initialDisabledCoordinatorConfig(chain), readers(), manager)
		require.ErrorContains(t, err, "before applying initial disabled selectors")
		require.Empty(t, manager.writes)
	})

	t.Run("write failure", func(t *testing.T) {
		manager := &initialDisabledStatusManager{writeErr: errors.New("write failed")}
		_, err := filterConfiguredSourceReaders(t.Context(), logger.Test(t), initialDisabledCoordinatorConfig(chain), readers(), manager)
		require.ErrorContains(t, err, "failed to persist initial disabled chain selectors")
	})
}

func TestFilterConfiguredSourceReaders_SeedsDisabledChainWithoutReader(t *testing.T) {
	const disabledChain protocol.ChainSelector = 1
	const activeChain protocol.ChainSelector = 2
	manager := &initialDisabledStatusManager{}
	config := initialDisabledCoordinatorConfig(disabledChain)
	config.SourceConfigs[activeChain] = vtypes.SourceConfig{}
	readers := map[protocol.ChainSelector]chainaccess.SourceReader{activeChain: mocks.NewMockSourceReader(t)}

	configured, err := filterConfiguredSourceReaders(t.Context(), logger.Test(t), config, readers, manager)
	require.NoError(t, err)
	require.Len(t, configured, 1)
	require.Contains(t, configured, activeChain)
	require.True(t, manager.statuses[disabledChain].Disabled)
}

func TestFilterConfiguredSourceReaders_ReadFailureWithoutSeedingRemainsNonFatal(t *testing.T) {
	const chain protocol.ChainSelector = 1
	manager := &initialDisabledStatusManager{readErr: errors.New("read failed")}
	readers := map[protocol.ChainSelector]chainaccess.SourceReader{chain: mocks.NewMockSourceReader(t)}
	config := CoordinatorConfig{SourceConfigs: map[protocol.ChainSelector]vtypes.SourceConfig{chain: {}}}

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	configured, err := filterConfiguredSourceReaders(ctx, logger.Test(t), config, readers, manager)
	require.NoError(t, err)
	require.Len(t, configured, 1)
}
