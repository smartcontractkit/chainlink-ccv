package messagerules

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// stubChecker is a stub common.MessageRulesCheckerService driven by canned IsMessageDisabled output.
type stubChecker struct {
	disabled bool
	err      error
}

func (s *stubChecker) IsMessageDisabled(context.Context, protocol.Message) (bool, error) {
	return s.disabled, s.err
}
func (s *stubChecker) Start(context.Context) error    { return nil }
func (s *stubChecker) Close() error                   { return nil }
func (s *stubChecker) Ready() error                   { return nil }
func (s *stubChecker) HealthReport() map[string]error { return map[string]error{} }
func (s *stubChecker) Name() string                   { return "stub" }

func checkerOf(t *testing.T, checkers ...NamedPoller) *MultiAggregatorRulesChecker {
	t.Helper()
	m, err := NewMultiAggregatorRulesChecker(logger.Test(t), nil, checkers...)
	require.NoError(t, err)
	return m
}

func TestMultiAggregatorRulesChecker_IsMessageDisabled(t *testing.T) {
	unknown := common.ErrMessageRulesStateUnknown

	tests := []struct {
		name         string
		checkers     []*stubChecker
		wantDisabled bool
		wantErr      error
	}{
		{
			name:         "none disable, all known -> not disabled",
			checkers:     []*stubChecker{{disabled: false}, {disabled: false}},
			wantDisabled: false,
			wantErr:      nil,
		},
		{
			name:         "any disables -> disabled, no error (drop)",
			checkers:     []*stubChecker{{disabled: false}, {disabled: true}},
			wantDisabled: true,
			wantErr:      nil,
		},
		{
			name:         "disabled wins over unknown from another source",
			checkers:     []*stubChecker{{err: unknown}, {disabled: true}},
			wantDisabled: true,
			wantErr:      nil,
		},
		{
			name:         "one up not disabled, one unknown -> relies on the up source, not disabled",
			checkers:     []*stubChecker{{disabled: false}, {err: unknown}},
			wantDisabled: false,
			wantErr:      nil,
		},
		{
			name:         "reachable sources disagree (one disabled, one enabled) -> disabled (more restrictive)",
			checkers:     []*stubChecker{{disabled: true}, {disabled: false}},
			wantDisabled: true,
			wantErr:      nil,
		},
		{
			name:         "only unknown sources -> blocked (fail closed)",
			checkers:     []*stubChecker{{err: unknown}, {err: unknown}},
			wantDisabled: true,
			wantErr:      unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			named := make([]NamedPoller, len(tt.checkers))
			for i, c := range tt.checkers {
				named[i] = NewNamedPoller("agg", c)
			}
			m := checkerOf(t, named...)

			disabled, err := m.IsMessageDisabled(context.Background(), protocol.Message{})
			assert.Equal(t, tt.wantDisabled, disabled)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMultiAggregatorRulesChecker_RequiresAtLeastOne(t *testing.T) {
	_, err := NewMultiAggregatorRulesChecker(logger.Test(t), nil)
	require.Error(t, err)
}

func TestMultiAggregatorRulesChecker_RecordsMismatchMetric(t *testing.T) {
	newChecker := func(metrics common.MessageRulesCheckerMetrics, checkers ...*stubChecker) *MultiAggregatorRulesChecker {
		named := make([]NamedPoller, len(checkers))
		for i, c := range checkers {
			named[i] = NewNamedPoller("agg", c)
		}
		m, err := NewMultiAggregatorRulesChecker(logger.Test(t), metrics, named...)
		require.NoError(t, err)
		return m
	}

	t.Run("disagreement records a mismatch", func(t *testing.T) {
		metrics := mocks.NewMockMessageRulesCheckerMetrics(t)
		metrics.EXPECT().RecordMessageDisablementRulesMismatch(mock.Anything).Once()
		m := newChecker(metrics, &stubChecker{disabled: true}, &stubChecker{disabled: false})
		disabled, err := m.IsMessageDisabled(context.Background(), protocol.Message{})
		require.NoError(t, err)
		assert.True(t, disabled)
	})

	t.Run("agreement records no mismatch", func(t *testing.T) {
		metrics := mocks.NewMockMessageRulesCheckerMetrics(t)
		m := newChecker(metrics, &stubChecker{disabled: true}, &stubChecker{disabled: true})
		disabled, err := m.IsMessageDisabled(context.Background(), protocol.Message{})
		require.NoError(t, err)
		assert.True(t, disabled)
	})

	t.Run("unknown source with agreement records no mismatch", func(t *testing.T) {
		metrics := mocks.NewMockMessageRulesCheckerMetrics(t)
		m := newChecker(metrics, &stubChecker{disabled: false}, &stubChecker{err: common.ErrMessageRulesStateUnknown})
		disabled, err := m.IsMessageDisabled(context.Background(), protocol.Message{})
		require.NoError(t, err)
		assert.False(t, disabled)
	})

	t.Run("all-unknown fail-closed records no mismatch", func(t *testing.T) {
		metrics := mocks.NewMockMessageRulesCheckerMetrics(t)
		m := newChecker(metrics, &stubChecker{err: common.ErrMessageRulesStateUnknown})
		disabled, err := m.IsMessageDisabled(context.Background(), protocol.Message{})
		require.ErrorIs(t, err, common.ErrMessageRulesStateUnknown)
		assert.True(t, disabled)
	})
}

func TestMultiAggregatorRulesChecker_StartCloseWiring(t *testing.T) {
	m := checkerOf(t,
		NewNamedPoller("a", &stubChecker{}),
		NewNamedPoller("b", &stubChecker{}),
	)
	require.NoError(t, m.Start(context.Background()))
	require.NoError(t, m.Close())
}
