package messagedisablement

import (
	"testing"
	"time"

	messagepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-rules/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ruleTestCase struct {
	Name  string
	Rule  Rule
	Proto messagepb.MessageRule
}

var staticCreatedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
var staticUpdatedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

var ruleTestCases = []ruleTestCase{
	{
		Name: "Chain rule",
		Rule: Rule{ID: "1", Type: RuleTypeChain, Data: []byte("{\"chain_selector\":1}"), CreatedAt: staticCreatedAt, UpdatedAt: staticUpdatedAt},
		Proto: messagepb.MessageRule{
			Id: "1",
			Condition: &messagepb.MessageRule_Chain{
				Chain: &messagepb.ChainMessageRule{
					ChainSelector: 1,
				},
			},
			CreatedAtUnixMillis: staticCreatedAt.UnixMilli(),
			UpdatedAtUnixMillis: staticUpdatedAt.UnixMilli(),
		},
	},
	{
		Name: "Lane rule",
		Rule: Rule{ID: "2", Type: RuleTypeLane, Data: []byte("{\"selector_a\":1, \"selector_b\":2}"), CreatedAt: staticCreatedAt, UpdatedAt: staticUpdatedAt},
		Proto: messagepb.MessageRule{
			Id: "2",
			Condition: &messagepb.MessageRule_Lane{
				Lane: &messagepb.LaneMessageRule{
					SelectorA: 1,
					SelectorB: 2,
				},
			},
			CreatedAtUnixMillis: staticCreatedAt.UnixMilli(),
			UpdatedAtUnixMillis: staticUpdatedAt.UnixMilli(),
		},
	},
	{
		Name: "Token rule",
		Rule: Rule{ID: "3", Type: RuleTypeToken, Data: []byte("{\"chain_selector\":1, \"token_address\":\"0x1234567890abcdef\"}"), CreatedAt: staticCreatedAt, UpdatedAt: staticUpdatedAt},
		Proto: messagepb.MessageRule{
			Id: "3",
			Condition: &messagepb.MessageRule_Token{
				Token: &messagepb.TokenMessageRule{
					ChainSelector: 1,
					TokenAddress:  []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef},
				},
			},
			CreatedAtUnixMillis: staticCreatedAt.UnixMilli(),
			UpdatedAtUnixMillis: staticUpdatedAt.UnixMilli(),
		},
	},
}

func TestRulesToProto(t *testing.T) {
	for _, tc := range ruleTestCases {
		t.Run(tc.Name, func(t *testing.T) {
			pbRule, err := RuleToProto(tc.Rule)
			require.NoError(t, err)
			assert.Equal(t, &tc.Proto, pbRule)
		})
	}
}
