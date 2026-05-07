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

	chainData, err := NewChainRuleData(10)
	require.NoError(t, err)
	laneData, err := NewLaneRuleData(30, 20)
	require.NoError(t, err)
	tokenData, err := NewTokenRuleData(40, "0x0102")
	require.NoError(t, err)
	chainRule, err := NewRule("chain", chainData, createdAt, updatedAt)
	require.NoError(t, err)
	laneRule, err := NewRule("lane", laneData, createdAt, updatedAt)
	require.NoError(t, err)
	tokenRule, err := NewRule("token", tokenData, createdAt, updatedAt)
	require.NoError(t, err)

	rules := []Rule{
		chainRule,
		laneRule,
		tokenRule,
	}

	pbRules, err := RulesToProto(rules)
	require.NoError(t, err)
	require.Equal(t, uint64(10), pbRules[0].GetChain().GetChainSelector())
	require.Equal(t, uint64(20), pbRules[1].GetLane().GetSelectorA())
	require.Equal(t, uint64(30), pbRules[1].GetLane().GetSelectorB())
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

	decodedTokenRule, err := decoded[2].TokenData()
	require.NoError(t, err)
	require.Equal(t, uint64(40), decodedTokenRule.ChainSelector)
	require.Equal(t, "0x0102", decodedTokenRule.TokenAddress)
}

func TestCompiledRulesMatchMessages(t *testing.T) {
	chainData, err := NewChainRuleData(10)
	require.NoError(t, err)
	laneData, err := NewLaneRuleData(30, 20)
	require.NoError(t, err)
	tokenData, err := NewTokenRuleData(40, "0x0102")
	require.NoError(t, err)
	chainRule, err := NewRule("chain", chainData, time.Time{}, time.Time{})
	require.NoError(t, err)
	laneRule, err := NewRule("lane", laneData, time.Time{}, time.Time{})
	require.NoError(t, err)
	tokenRule, err := NewRule("token", tokenData, time.Time{}, time.Time{})
	require.NoError(t, err)

	compiled, err := CompileRules([]Rule{chainRule, laneRule, tokenRule})
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

	snapshot := compiled.RulesSnapshot()
	require.Len(t, snapshot, 3)
	laneSnapshot, err := snapshot[1].LaneData()
	require.NoError(t, err)
	require.Equal(t, uint64(20), laneSnapshot.SelectorA)
	require.Equal(t, uint64(30), laneSnapshot.SelectorB)
}

func TestRuleDataJSONBoundary(t *testing.T) {
	laneData, err := DecodeRuleData(RuleTypeLane, []byte(`{"selector_a":30,"selector_b":20}`))
	require.NoError(t, err)

	ruleType, raw, err := EncodeRuleData(laneData)
	require.NoError(t, err)
	require.Equal(t, RuleTypeLane, ruleType)
	require.JSONEq(t, `{"selector_a":20,"selector_b":30}`, string(raw))

	tokenData, err := DecodeRuleData(RuleTypeToken, []byte(`{"chain_selector":40,"token_address":"AA"}`))
	require.NoError(t, err)
	_, raw, err = EncodeRuleData(tokenData)
	require.NoError(t, err)
	require.JSONEq(t, `{"chain_selector":40,"token_address":"0xaa"}`, string(raw))

	_, err = DecodeRuleData(RuleTypeChain, []byte(`{"chain_selector":0}`))
	require.Error(t, err)
}
