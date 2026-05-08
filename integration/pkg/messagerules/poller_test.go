package messagerules

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common"
	shared "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestPollerService_UnknownUntilSuccessfulPoll(t *testing.T) {
	metrics := mocks.NewMockMessageRulesCheckerMetrics(t)
	metrics.EXPECT().SetMessageDisablementRulesRefreshFailure(mock.Anything, int64(1))
	client := mocks.NewMockClient(t)
	client.EXPECT().ListMessageRules(mock.Anything).Return(nil, errors.New("boom"))
	client.EXPECT().Close().Return(nil)
	svc, err := NewPollerService(client, time.Hour, time.Hour, logger.Test(t), metrics)
	require.NoError(t, err)

	err = svc.Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, svc.Close()) })

	disabled, err := svc.IsMessageDisabled(context.Background(), protocol.Message{})
	require.True(t, disabled)
	require.ErrorIs(t, err, common.ErrMessageRulesStateUnknown)
}

func TestPollerService_UsesLastSuccessfulRules(t *testing.T) {
	metrics := mocks.NewMockMessageRulesCheckerMetrics(t)
	metrics.EXPECT().SetMessageDisablementRulesRefreshFailure(mock.Anything, int64(0))
	client := mocks.NewMockClient(t)
	client.EXPECT().Close().Return(nil)
	data, err := shared.NewChainRuleData(10)
	require.NoError(t, err)
	client.EXPECT().ListMessageRules(mock.Anything).Return([]shared.Rule{{ID: "rule", Type: shared.RuleTypeChain, Data: data}}, nil).Once()
	svc, err := NewPollerService(client, time.Hour, time.Hour, logger.Test(t), metrics)
	require.NoError(t, err)

	err = svc.Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, svc.Close()) })

	require.Eventually(t, func() bool {
		disabled, err := svc.IsMessageDisabled(context.Background(), protocol.Message{SourceChainSelector: 10, DestChainSelector: 20})
		return err == nil && disabled
	}, time.Second, time.Millisecond)

	metrics.EXPECT().SetMessageDisablementRulesRefreshFailure(mock.Anything, int64(1))
	client.EXPECT().ListMessageRules(mock.Anything).Return(nil, errors.New("transient"))
	svc.poll(context.Background())

	require.Eventually(t, func() bool {
		disabled, err := svc.IsMessageDisabled(context.Background(), protocol.Message{SourceChainSelector: 10, DestChainSelector: 20})
		return err == nil && disabled
	}, time.Second, time.Millisecond)
}
