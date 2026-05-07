package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	messagerules "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	messagepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-rules/v1"
)

type fakeMessageRulesRegistry struct {
	rules []messagerules.Rule
	ok    bool
}

func (f fakeMessageRulesRegistry) ActiveRulesSnapshot() ([]messagerules.Rule, bool) {
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

	chainData, err := messagerules.NewChainRuleData(10)
	require.NoError(t, err)
	laneData, err := messagerules.NewLaneRuleData(20, 10)
	require.NoError(t, err)
	tokenData, err := messagerules.NewTokenRuleData(30, "0x0102")
	require.NoError(t, err)
	chainRule, err := messagerules.NewRule("chain", chainData, createdAt, updatedAt)
	require.NoError(t, err)
	laneRule, err := messagerules.NewRule("lane", laneData, createdAt, updatedAt)
	require.NoError(t, err)
	tokenRule, err := messagerules.NewRule("token", tokenData, createdAt, updatedAt)
	require.NoError(t, err)

	handler := NewListMessageRulesHandler(fakeMessageRulesRegistry{
		ok:    true,
		rules: []messagerules.Rule{chainRule, laneRule, tokenRule},
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
