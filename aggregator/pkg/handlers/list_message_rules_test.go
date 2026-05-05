package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/messagedisablement"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	messagepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-rules/v1"
)

type fakeMessageRulesRegistry struct {
	rules []messagedisablement.Rule
	ok    bool
}

func (f fakeMessageRulesRegistry) ActiveRulesSnapshot() ([]messagedisablement.Rule, bool) {
	return f.rules, f.ok
}

func TestListMessageRulesHandler_UnavailableBeforeRefresh(t *testing.T) {
	handler := NewListMessageRulesHandler(fakeMessageRulesRegistry{}, logger.Sugared(logger.Test(t)))

	resp, err := handler.Handle(context.Background(), &messagepb.ListMessageRulesRequest{})
	require.Nil(t, resp)
	require.Error(t, err)
	require.Equal(t, codes.Unavailable, grpcstatus.Code(err))
}

func TestListMessageRulesHandler_ReturnsActiveRules(t *testing.T) {
	createdAt := time.UnixMilli(1000).UTC()
	updatedAt := time.UnixMilli(2000).UTC()

	chainData, err := messagedisablement.NewChainRuleData(10)
	require.NoError(t, err)
	laneData, err := messagedisablement.NewLaneRuleData(20, 10)
	require.NoError(t, err)
	tokenData, err := messagedisablement.NewTokenRuleData(30, "0x0102")
	require.NoError(t, err)

	handler := NewListMessageRulesHandler(fakeMessageRulesRegistry{
		ok: true,
		rules: []messagedisablement.Rule{
			{ID: "chain", Type: messagedisablement.RuleTypeChain, Data: chainData, CreatedAt: createdAt, UpdatedAt: updatedAt},
			{ID: "lane", Type: messagedisablement.RuleTypeLane, Data: laneData, CreatedAt: createdAt, UpdatedAt: updatedAt},
			{ID: "token", Type: messagedisablement.RuleTypeToken, Data: tokenData, CreatedAt: createdAt, UpdatedAt: updatedAt},
		},
	}, logger.Sugared(logger.Test(t)))

	resp, err := handler.Handle(context.Background(), &messagepb.ListMessageRulesRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetRules(), 3)

	require.Equal(t, uint64(10), resp.GetRules()[0].GetChain().GetChainSelector())
	require.Equal(t, uint64(10), resp.GetRules()[1].GetLane().GetSelectorA())
	require.Equal(t, uint64(20), resp.GetRules()[1].GetLane().GetSelectorB())
	require.Equal(t, uint64(30), resp.GetRules()[2].GetToken().GetChainSelector())
	require.Equal(t, []byte{0x01, 0x02}, resp.GetRules()[2].GetToken().GetTokenAddress())
	require.Equal(t, int64(1000), resp.GetRules()[0].GetCreatedAtUnixMillis())
	require.Equal(t, int64(2000), resp.GetRules()[0].GetUpdatedAtUnixMillis())
}
