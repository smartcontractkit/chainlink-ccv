package verifiercli

import (
	"context"
	"strconv"
	"strings"
)

// ChainStatusesSubcommand is the CLI path used to reach the
// chain-statuses commands: `ccv chain-statuses ...`.
var ChainStatusesSubcommand = []string{"ccv", "chain-statuses"}

// ChainSelector is a decimal-encoded chain selector as expected by the
// CLI's --chain-selector flag. Kept as a named type so test code cannot
// accidentally pass an unrelated uint64.
type ChainSelector string

// FormatChainSelector renders sel for use with the CLI.
func FormatChainSelector(sel uint64) ChainSelector {
	return ChainSelector(strconv.FormatUint(sel, 10))
}

// BlockHeight is a decimal-encoded block height as expected by the
// CLI's --block-height flag.
type BlockHeight string

// FormatBlockHeight renders height for CLI use.
func FormatBlockHeight(height uint64) BlockHeight {
	return BlockHeight(strconv.FormatUint(height, 10))
}

// ChainStatusesClient is the thin wrapper around the ccv chain-statuses
// CLI group. Obtain via (*Client).ChainStatuses().
type ChainStatusesClient struct {
	client *Client
}

// ChainStatuses returns a sub-client for the chain-statuses CLI. The
// returned value is a tiny struct; constructing one is free.
func (c *Client) ChainStatuses() ChainStatusesClient {
	return ChainStatusesClient{client: c}
}

// List runs `chain-statuses list` and returns the raw table output.
func (s ChainStatusesClient) List(ctx context.Context) (string, error) {
	return s.client.CLI(ctx, ChainStatusesSubcommand, "list")
}

// Disable runs `chain-statuses disable`. The CLI refuses to run while
// the committee process is live; callers typically Pause() first.
func (s ChainStatusesClient) Disable(ctx context.Context, sel ChainSelector, verifierID string) (string, error) {
	return s.client.CLI(ctx, ChainStatusesSubcommand,
		"disable", "--chain-selector", string(sel), "--verifier-id", verifierID)
}

// Enable runs `chain-statuses enable`.
func (s ChainStatusesClient) Enable(ctx context.Context, sel ChainSelector, verifierID string) (string, error) {
	return s.client.CLI(ctx, ChainStatusesSubcommand,
		"enable", "--chain-selector", string(sel), "--verifier-id", verifierID)
}

// SetFinalizedHeight runs `chain-statuses set-finalized-height`, which
// rewinds (or advances) the per-chain checkpoint the verifier uses to
// resume scanning.
func (s ChainStatusesClient) SetFinalizedHeight(ctx context.Context, sel ChainSelector, verifierID string, height BlockHeight) (string, error) {
	return s.client.CLI(ctx, ChainStatusesSubcommand,
		"set-finalized-height",
		"--chain-selector", string(sel),
		"--verifier-id", verifierID,
		"--block-height", string(height))
}

// ParseFirstListRow extracts the chain selector from the first data row
// of a `chain-statuses list` table. Returns ok=false when the list is
// empty or the header is all that's present.
//
// The parse is deliberately lenient: it skips the header row, dashed
// separators, and any row whose selector column is not a uint. This
// matches tablewriter output without coupling to column count.
func ParseFirstListRow(listOutput string) (sel ChainSelector, ok bool) {
	if strings.Contains(listOutput, "No chain status rows found.") {
		return "", false
	}
	for line := range strings.SplitSeq(listOutput, "\n") {
		if !strings.Contains(line, "|") {
			continue
		}
		parts := strings.Split(line, "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) < 2 {
			continue
		}
		// Skip header - it contains the literal "verifier_id".
		if strings.Contains(parts[0], "Chain") && strings.Contains(line, "verifier_id") {
			continue
		}
		// Skip separator rows like |------|------|.
		if strings.TrimLeft(line, "-+| \t") == "" {
			continue
		}
		candidate := parts[1]
		if _, err := strconv.ParseUint(candidate, 10, 64); err != nil {
			continue
		}
		return ChainSelector(candidate), true
	}
	return "", false
}
