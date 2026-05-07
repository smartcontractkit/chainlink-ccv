package aggregatorcli

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
)

var MessageDisablementRulesSubcommand = []string{"message-disablement-rules"}

type ChainSelector string

func FormatChainSelector(sel uint64) ChainSelector {
	return ChainSelector(strconv.FormatUint(sel, 10))
}

type RuleID string

type MessageDisablementRulesClient struct {
	client *Client
}

func (c *Client) MessageDisablementRules() MessageDisablementRulesClient {
	return MessageDisablementRulesClient{client: c}
}

func (rc MessageDisablementRulesClient) List(ctx context.Context, args ...string) (string, error) {
	return rc.client.CLI(ctx, MessageDisablementRulesSubcommand, append([]string{"list"}, args...)...)
}

func (rc MessageDisablementRulesClient) Get(ctx context.Context, id RuleID) (string, error) {
	return rc.client.CLI(ctx, MessageDisablementRulesSubcommand, "get", "--id", string(id))
}

func (rc MessageDisablementRulesClient) Delete(ctx context.Context, id RuleID) (string, error) {
	return rc.client.CLI(ctx, MessageDisablementRulesSubcommand, "delete", "--id", string(id))
}

func (rc MessageDisablementRulesClient) CreateChain(ctx context.Context, selector ChainSelector) (string, error) {
	return rc.client.CLI(ctx, MessageDisablementRulesSubcommand, "create", "chain", "--chain", string(selector))
}

func (rc MessageDisablementRulesClient) CreateLane(ctx context.Context, selectorA, selectorB ChainSelector) (string, error) {
	return rc.client.CLI(ctx, MessageDisablementRulesSubcommand, "create", "lane", "--lane", fmt.Sprintf("%s,%s", selectorA, selectorB))
}

func (rc MessageDisablementRulesClient) CreateToken(ctx context.Context, selector ChainSelector, tokenAddress string) (string, error) {
	return rc.client.CLI(ctx, MessageDisablementRulesSubcommand, "create", "token", "--token", fmt.Sprintf("%s,%s", selector, tokenAddress))
}

func ParseRuleID(output string) (RuleID, error) {
	match := regexp.MustCompile(`id=([0-9a-f-]{36})`).FindStringSubmatch(output)
	if len(match) != 2 {
		return "", fmt.Errorf("rule id not found in output: %s", output)
	}
	return RuleID(match[1]), nil
}
