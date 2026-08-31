package verifiercli

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	// chainStatusRowWaitTimeout bounds how long the wait helpers poll the
	// chain-statuses table. It must comfortably exceed the verifier's
	// chain-status batcher flush interval (DefaultFlushInterval, 30s) plus
	// source-reader startup so a row is guaranteed to appear.
	chainStatusRowWaitTimeout = 90 * time.Second
	// chainStatusRowWaitInterval is the poll interval while waiting for
	// chain-status rows.
	chainStatusRowWaitInterval = 2 * time.Second
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

// WaitForFirstRow polls `chain-statuses list` until at least one row is
// present and returns the first row's chain selector.
//
// The CLI reads a Postgres table that the running verifier fills only on
// its chain-status batcher flush (default 30s), so a freshly started (or
// just restarted) verifier can expose an empty table for a little while.
// Tests that then go on to disable / set-finalized-height - operations
// that UPDATE an existing row - must wait for the row to appear first so
// the CLI does not fail with "no row found".
func (s ChainStatusesClient) WaitForFirstRow(ctx context.Context) (ChainSelector, error) {
	lastOut, err := s.waitFor(ctx, func(out string) bool {
		_, ok := ParseFirstListRow(out)
		return ok
	})
	if err != nil {
		return "", fmt.Errorf(
			"no chain status row present for %s within %s; last list output: %s",
			s.client.Container(), chainStatusRowWaitTimeout, lastOut)
	}
	sel, _ := ParseFirstListRow(lastOut)
	return sel, nil
}

// WaitForRow polls `chain-statuses list` until a row for want is present.
// The verifier's batcher flushes all monitored chains in a single flush,
// so this also guarantees the rest of the table is populated.
func (s ChainStatusesClient) WaitForRow(ctx context.Context, want ChainSelector) error {
	lastOut, err := s.waitFor(ctx, func(out string) bool {
		_, ok := ParseFirstListRow(out)
		return ok && strings.Contains(out, string(want))
	})
	if err != nil {
		return fmt.Errorf(
			"no chain status row for selector %s within %s (container %s); last list output: %s",
			want, chainStatusRowWaitTimeout, s.client.Container(), lastOut)
	}
	return nil
}

// waitFor polls `chain-statuses list` until predicate returns true for the
// output, bounded by chainStatusRowWaitTimeout. On timeout it returns the
// most recently seen list output so callers can include it in their error.
func (s ChainStatusesClient) waitFor(ctx context.Context, predicate func(out string) bool) (string, error) {
	waitCtx, cancel := context.WithTimeout(ctx, chainStatusRowWaitTimeout)
	defer cancel()

	ticker := time.NewTicker(chainStatusRowWaitInterval)
	defer ticker.Stop()

	var lastOut string
	for {
		select {
		case <-waitCtx.Done():
			return lastOut, waitCtx.Err()
		case <-ticker.C:
			out, err := s.List(waitCtx)
			if err != nil {
				// The CLI may still be booting; keep polling.
				continue
			}
			lastOut = out
			if predicate(out) {
				return out, nil
			}
		}
	}
}

// ParseFirstListRow extracts the chain selector from the first data row
// of a `chain-statuses list` table. Returns ok=false when the list is
// empty or the header is all that's present.
//
// The parse is deliberately lenient: it skips log lines, the header row,
// dashed separators, and any row whose selector column is not a uint.
// This supports both the legacy pipe-delimited tablewriter output and the
// newer plain whitespace-delimited table style without coupling to exact
// column counts.
func ParseFirstListRow(listOutput string) (sel ChainSelector, ok bool) {
	if strings.Contains(listOutput, "No chain status rows found.") {
		return "", false
	}
	for line := range strings.SplitSeq(listOutput, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "goose:") || strings.Contains(line, `"level":"`) || strings.Contains(line, " level=") {
			continue
		}
		// Skip header rows - they contain the literal "verifier_id".
		if strings.Contains(line, "verifier_id") {
			continue
		}
		// Skip separator rows like |------|------| or ----- -----.
		if strings.TrimLeftFunc(line, func(r rune) bool {
			return r == '-' || r == '+' || r == '|' || unicode.IsSpace(r)
		}) == "" {
			continue
		}
		candidate, found := parseChainSelectorColumn(line)
		if !found {
			continue
		}
		if _, err := strconv.ParseUint(candidate, 10, 64); err != nil {
			continue
		}
		return ChainSelector(candidate), true
	}
	return "", false
}

func parseChainSelectorColumn(line string) (string, bool) {
	if strings.Contains(line, "|") {
		for part := range strings.SplitSeq(line, "|") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, err := strconv.ParseUint(part, 10, 64); err == nil {
				return part, true
			}
		}
		return "", false
	}

	for field := range strings.FieldsSeq(line) {
		if _, err := strconv.ParseUint(field, 10, 64); err == nil {
			return field, true
		}
	}
	return "", false
}
