package messagerules

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common"
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

func unionOf(t *testing.T, checkers ...NamedPoller) *UnionPollerService {
	t.Helper()
	u, err := NewUnionPollerService(logger.Test(t), checkers...)
	require.NoError(t, err)
	return u
}

func TestUnionPoller_IsMessageDisabled(t *testing.T) {
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
			name:         "disabled wins over unknown",
			checkers:     []*stubChecker{{err: unknown}, {disabled: true}},
			wantDisabled: true,
			wantErr:      nil,
		},
		{
			name:         "any unknown and none disable -> blocked (strict fail-safe)",
			checkers:     []*stubChecker{{disabled: false}, {err: unknown}},
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
			u := unionOf(t, named...)

			disabled, err := u.IsMessageDisabled(context.Background(), protocol.Message{})
			assert.Equal(t, tt.wantDisabled, disabled)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestUnionPoller_RequiresAtLeastOne(t *testing.T) {
	_, err := NewUnionPollerService(logger.Test(t))
	require.Error(t, err)
}

func TestUnionPoller_StartCloseWiring(t *testing.T) {
	u := unionOf(t,
		NewNamedPoller("a", &stubChecker{}),
		NewNamedPoller("b", &stubChecker{}),
	)
	require.NoError(t, u.Start(context.Background()))
	require.NoError(t, u.Close())
}
