package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/verifiercli"
)

// removeBlocksTimeout covers remove-blocks waiting for a paused verifier's EVM database lease to expire.
const removeBlocksTimeout = 2 * time.Minute

// committeeReadsThroughLogPoller reports whether the committee reads chainSelector through the LogPoller.
// Every member must agree, since the finality-violation recovery differs between the two readers.
func committeeReadsThroughLogPoller(t *testing.T, in *ccv.Cfg, verifierID string, chainSelector uint64) bool {
	t.Helper()
	chainID, err := chain_selectors.GetChainIDFromSelector(chainSelector)
	require.NoError(t, err)

	var readers []bool
	for _, v := range in.Verifier {
		if v.Out == nil || v.Out.VerifierID != verifierID {
			continue
		}
		on, err := evm.LogPollerSourceReaderOn(v, chainID)
		require.NoError(t, err)
		readers = append(readers, on)
	}
	require.NotEmpty(t, readers, "no verifier in committee %s", verifierID)
	for _, on := range readers[1:] {
		require.Equal(t, readers[0], on, "committee %s mixes LogPoller and RPC readers on chain %s", verifierID, chainID)
	}
	return readers[0]
}

// requireLogPollerFinalityRecovery resolves a finality violation on every member the way
// docs/runbooks/resolving-finality-violation.md does for a standalone verifier.
func requireLogPollerFinalityRecovery(t *testing.T, ctx context.Context, committee *verifiercli.CommitteeClient, chainSelector uint64) {
	t.Helper()
	chainID, err := chain_selectors.GetChainIDFromSelector(chainSelector)
	require.NoError(t, err)
	sel := verifiercli.FormatChainSelector(chainSelector)

	for _, member := range committee.Members() {
		lca, err := member.Blocks().FindLCA(ctx, chainID)
		require.NoError(t, err, "find-lca on %s", member.Container())

		require.NoError(t, member.Pause(ctx), "pause %s before remove-blocks", member.Container())
		t.Cleanup(func() { member.ResumeBestEffort(context.Background()) })
		removeCtx, cancel := context.WithTimeout(ctx, removeBlocksTimeout)
		out, err := member.Blocks().RemoveFrom(removeCtx, chainID, lca+1)
		cancel()
		require.NoError(t, err, "remove-blocks on %s: %s", member.Container(), out)

		_, err = member.ChainStatuses().SetFinalizedHeight(ctx, sel, committee.VerifierID(), verifiercli.FormatBlockHeight(lca))
		require.NoError(t, err, "set-finalized-height on %s", member.Container())
		_, err = member.ChainStatuses().Enable(ctx, sel, committee.VerifierID())
		require.NoError(t, err, "enable on %s", member.Container())
		require.NoError(t, member.RestartAndWaitReady(ctx), "restart %s", member.Container())
	}
}
