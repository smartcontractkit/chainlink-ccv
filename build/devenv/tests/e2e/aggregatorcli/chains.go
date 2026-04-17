package aggregatorcli

import (
	"context"
	"strconv"
)

// ChainsSubcommand is the CLI path used to reach the chains commands:
// `aggregator chains ...`.
var ChainsSubcommand = []string{"chains"}

// ChainSelector is a decimal-encoded chain selector as expected by the
// CLI's --source / --destination flags.
type ChainSelector string

// FormatChainSelector renders sel for use with the CLI.
func FormatChainSelector(sel uint64) ChainSelector {
	return ChainSelector(strconv.FormatUint(sel, 10))
}

// ChainsClient is the thin wrapper around the aggregator chains CLI group.
// Obtain via (*Client).Chains().
type ChainsClient struct {
	client *Client
}

// Chains returns a sub-client for the chains CLI. The returned value is a
// tiny struct; constructing one is free.
func (c *Client) Chains() ChainsClient {
	return ChainsClient{client: c}
}

// List runs `chains list` and returns the raw table output.
func (cs ChainsClient) List(ctx context.Context) (string, error) {
	return cs.client.CLI(ctx, ChainsSubcommand, "list")
}

// Disable runs `chains disable <args...>`. Pass flag pairs such as
// "--source", "12345" or "--all".
func (cs ChainsClient) Disable(ctx context.Context, args ...string) (string, error) {
	return cs.client.CLI(ctx, ChainsSubcommand, append([]string{"disable"}, args...)...)
}

// Enable runs `chains enable <args...>`. Pass flag pairs such as
// "--source", "12345" or "--all".
func (cs ChainsClient) Enable(ctx context.Context, args ...string) (string, error) {
	return cs.client.CLI(ctx, ChainsSubcommand, append([]string{"enable"}, args...)...)
}
