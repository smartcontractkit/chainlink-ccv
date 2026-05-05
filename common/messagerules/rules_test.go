package messagerules

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type testMessageReport struct {
	source protocol.ChainSelector
	dest   protocol.ChainSelector
	tt     *protocol.TokenTransfer
}

func (r testMessageReport) GetSourceChainSelector() uint64 {
	return uint64(r.source)
}

func (r testMessageReport) GetDestinationSelector() uint64 {
	return uint64(r.dest)
}

func (r testMessageReport) GetTokenTransfer() *protocol.TokenTransfer {
	return r.tt
}

func TestRuleProtoRoundTrip(t *testing.T) {
	createdAt := time.UnixMilli(1000).UTC()
	updatedAt := time.UnixMilli(2000).UTC()

	rules := []Rule{
		{ID: "chain", Type: RuleTypeChain, data: ChainRuleData{ChainSelector: 10}, CreatedAt: createdAt, UpdatedAt: updatedAt},
		{ID: "lane", Type: RuleTypeLane, data: LaneRuleData{SelectorA: 30, SelectorB: 20}, CreatedAt: createdAt, UpdatedAt: updatedAt},
		{ID: "token", Type: RuleTypeToken, data: TokenRuleData{ChainSelector: 40, TokenAddress: "0x0102"}, CreatedAt: createdAt, UpdatedAt: updatedAt},
	}

	pbRules, err := RulesToProto(rules)
	require.NoError(t, err)
	require.Equal(t, uint64(10), pbRules[0].GetChain().GetChainSelector())
	require.Equal(t, uint64(30), pbRules[1].GetLane().GetSelectorA())
	require.Equal(t, uint64(20), pbRules[1].GetLane().GetSelectorB())
	require.Equal(t, uint64(40), pbRules[2].GetToken().GetChainSelector())
	require.Equal(t, []byte{0x01, 0x02}, pbRules[2].GetToken().GetTokenAddress())
	require.Equal(t, int64(1000), pbRules[0].GetCreatedAtUnixMillis())
	require.Equal(t, int64(2000), pbRules[0].GetUpdatedAtUnixMillis())

	decoded, err := RulesFromProto(pbRules)
	require.NoError(t, err)
	require.Len(t, decoded, len(rules))
	require.Equal(t, RuleTypeChain, decoded[0].Type)
	require.Equal(t, RuleTypeLane, decoded[1].Type)
	require.Equal(t, RuleTypeToken, decoded[2].Type)
	require.Equal(t, createdAt, decoded[0].CreatedAt)
	require.Equal(t, updatedAt, decoded[0].UpdatedAt)

	tokenRule, err := decoded[2].TokenData()
	require.NoError(t, err)
	require.Equal(t, uint64(40), tokenRule.ChainSelector)
	require.Equal(t, "0x0102", tokenRule.TokenAddress)
}

func TestCompiledRulesMatchMessages(t *testing.T) {
	compiled, err := CompileRules([]Rule{
		{ID: "chain", Type: RuleTypeChain, data: ChainRuleData{ChainSelector: 10}},
		{ID: "lane", Type: RuleTypeLane, data: LaneRuleData{SelectorA: 30, SelectorB: 20}},
		{ID: "token", Type: RuleTypeToken, data: TokenRuleData{ChainSelector: 40, TokenAddress: "0x0102"}},
	})
	require.NoError(t, err)

	require.True(t, compiled.IsDisabled(testMessageReport{source: 10, dest: 99}))
	require.True(t, compiled.IsDisabled(testMessageReport{source: 30, dest: 20}))
	require.True(t, compiled.IsDisabled(testMessageReport{
		source: 1,
		dest:   40,
		tt: &protocol.TokenTransfer{
			DestTokenAddress: protocol.ByteSlice{0x01, 0x02},
		},
	}))
	require.False(t, compiled.IsDisabled(testMessageReport{source: 1, dest: 2}))
	require.Equal(t, 3, compiled.ActiveRuleCount())
	require.Equal(t, RuleCounts{Chain: 1, Lane: 1, Token: 1}, compiled.RuleCounts())

	snapshot := compiled.RulesSnapshot()
	require.Len(t, snapshot, 3)
	laneSnapshot, err := snapshot[1].LaneData()
	require.NoError(t, err)
	require.Equal(t, uint64(30), laneSnapshot.SelectorA)
	require.Equal(t, uint64(20), laneSnapshot.SelectorB)
}
