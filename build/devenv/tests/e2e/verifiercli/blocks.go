package verifiercli

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
)

// BlocksSubcommand is the CLI path to the LogPoller block commands: `ccv blocks ...`.
var BlocksSubcommand = []string{"ccv", "blocks"}

// lcaBlockNumber matches the block number line find-lca prints.
var lcaBlockNumber = regexp.MustCompile(`(?m)^Block Number:\s*(\d+)\s*$`)

// BlocksClient wraps the ccv blocks CLI group. Obtain via (*Client).Blocks().
type BlocksClient struct {
	client *Client
}

// Blocks returns a sub-client for the ccv blocks CLI.
func (c *Client) Blocks() BlocksClient {
	return BlocksClient{client: c}
}

// FindLCA runs `blocks find-lca` and returns the last common ancestor's block number.
func (b BlocksClient) FindLCA(ctx context.Context, evmChainID string) (uint64, error) {
	out, err := b.client.CLI(ctx, BlocksSubcommand, "find-lca", "--evm-chain-id", evmChainID)
	if err != nil {
		return 0, err
	}
	return ParseLCABlockNumber(out)
}

// RemoveFrom runs `blocks remove-blocks` from start, start included. It waits for the EVM database
// lease, so the verifier must be paused or stopped first.
func (b BlocksClient) RemoveFrom(ctx context.Context, evmChainID string, start uint64) (string, error) {
	return b.client.CLI(ctx, BlocksSubcommand,
		"remove-blocks", "--evm-chain-id", evmChainID, "--start", strconv.FormatUint(start, 10))
}

// ParseLCABlockNumber reads the block number from find-lca output.
func ParseLCABlockNumber(out string) (uint64, error) {
	m := lcaBlockNumber.FindStringSubmatch(out)
	if m == nil {
		return 0, fmt.Errorf("no block number in find-lca output: %s", out)
	}
	return strconv.ParseUint(m[1], 10, 64)
}
