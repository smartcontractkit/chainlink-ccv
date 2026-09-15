package e2e

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/verifiercli"
)

// requireLiveRangeRecovery covers only live operations. No pause/restart helper
// is used, and process start ticks must remain identical on every member.
func requireLiveRangeRecovery(t *testing.T, ctx context.Context, committee *verifiercli.CommitteeClient, chain, from uint64, to *uint64, mode string) {
	t.Helper()
	for _, member := range committee.Members() {
		if to == nil {
			// Wait for a head observation after the caller's canonical-chain changes.
			// This also avoids selecting a stale pre-reorg height in manual-mining tests.
			started := time.Now()
			require.Eventually(t, func() bool {
				page, err := member.Recovery().Events(ctx, committee.VerifierID(), strconv.FormatUint(chain, 10), "")
				if err != nil {
					return false
				}
				var readers []struct {
					HeadObservedAt *time.Time `json:"head_observed_at"`
				}
				if json.Unmarshal(page.Readers, &readers) != nil || len(readers) != 1 {
					return false
				}
				return readers[0].HeadObservedAt != nil && readers[0].HeadObservedAt.After(started)
			}, time.Minute, time.Second, "reader must advertise a current canonical head")
		}
		identity, err := member.ProcessIdentity(ctx)
		require.NoError(t, err)
		o, err := member.Recovery().Submit(ctx, mode, committee.VerifierID(), strconv.FormatUint(chain, 10), from, to, "")
		require.NoError(t, err, "submit recovery on %s", member.Container())
		require.NotEmpty(t, o.ID)
		completed, err := member.Recovery().Wait(ctx, o.ID)
		require.NoError(t, err, "recover on %s", member.Container())
		require.Equal(t, completed.ToBlock+1, completed.NextBlock)
		after, err := member.ProcessIdentity(ctx)
		require.NoError(t, err)
		require.Equal(t, identity, after, "live recovery must not restart %s", member.Container())
	}
}

func requireRecoveryDropEvidence(t *testing.T, ctx context.Context, committee *verifiercli.CommitteeClient, chain uint64, messageID, reason string) uint64 {
	t.Helper()
	var block uint64
	for _, member := range committee.Members() {
		require.Eventually(t, func() bool {
			page, err := member.Recovery().Events(ctx, committee.VerifierID(), strconv.FormatUint(chain, 10), reason, messageID)
			if err != nil || len(page.Events) == 0 || page.Events[0].SourceBlock == nil {
				return false
			}
			e := page.Events[0]
			if e.MessageID == nil || *e.MessageID != messageID || e.Kind != "drop" {
				return false
			}
			block, err = strconv.ParseUint(*e.SourceBlock, 10, 64)
			return err == nil && page.Coverage != "" && e.NodeID != ""
		}, time.Minute, time.Second, "member %s must persist %s evidence", member.Container(), reason)
	}
	return block
}
