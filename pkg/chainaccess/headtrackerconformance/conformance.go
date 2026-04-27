package headtrackerconformance

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// Oracle is an independent read path to verify HeadTracker output (e.g. direct
// JSON-RPC to a node, not the HeadTracker stack). Implementations should
// return the same canonical [protocol.BlockHeader] fields a full node would
// return for that block height.
type Oracle interface {
	BlockHeaderByNumber(ctx context.Context, number uint64) (*protocol.BlockHeader, error)
}

// SafeExpectation defines how [chainaccess.HeadTracker.LatestSafeBlock] should behave for the test run.
type SafeExpectation int

const (
	// SafeAny: both (nil, nil) and a non-nil safe header are valid; if non-nil, it must match the oracle.
	SafeAny SafeExpectation = iota
	// SafeMustBeNil: the chain has no "safe" concept; LatestSafeBlock must return (nil, nil).
	SafeMustBeNil
	// SafeMustBePresent: the chain has a safe head; LatestSafeBlock must return a non-nil header
	// that matches the oracle and (with the same [LatestAndFinalizedBlock] snapshot) satisfies
	// finalized.Number <= safe.Number <= latest.Number when applicable.
	SafeMustBePresent
)

// Config wires a [chainaccess.HeadTracker], an [Oracle], and safe-head expectations.
type Config struct {
	HeadTracker chainaccess.HeadTracker
	Oracle      Oracle
	Safe        SafeExpectation
}

// Run executes the conformance subtests. ctx may be nil (uses [context.Background]).
// Panics in tests are avoided by using require from testify; callers use *testing.T as usual.
func Run(t *testing.T, ctx context.Context, cfg Config) {
	t.Helper()
	if ctx == nil {
		ctx = context.Background()
	}
	require.NotNil(t, cfg.HeadTracker, "HeadTracker")
	require.NotNil(t, cfg.Oracle, "Oracle")

	t.Run("LatestAndFinalizedBlock", func(t *testing.T) {
		latest, fin, err := cfg.HeadTracker.LatestAndFinalizedBlock(ctx)
		require.NoError(t, err)
		require.NotNil(t, latest, "latest")
		require.NotNil(t, fin, "finalized")
		headersOrderedByNumber(t, fin, latest, "finalized and latest")
		assertHeaderMatchesOracle(t, ctx, cfg.Oracle, "latest", latest)
		assertHeaderMatchesOracle(t, ctx, cfg.Oracle, "finalized", fin)
	})

	t.Run("LatestAndFinalizedBlock_invariants", func(t *testing.T) {
		// Parent chain sanity: if parent of latest is at latest-1 in the simple case,
		// implementations may still be correct with gaps; we only require finalized <= latest.
		latest, fin, err := cfg.HeadTracker.LatestAndFinalizedBlock(ctx)
		require.NoError(t, err)
		require.NotNil(t, latest)
		require.NotNil(t, fin)
		require.LessOrEqual(t, fin.Number, latest.Number)
	})

	t.Run("LatestSafeBlock", func(t *testing.T) {
		// Snapshot latest/fin and safe in order so ordering checks use one view as much as possible.
		latest, fin, err := cfg.HeadTracker.LatestAndFinalizedBlock(ctx)
		require.NoError(t, err)
		safe, err := cfg.HeadTracker.LatestSafeBlock(ctx)
		require.NoError(t, err)

		switch cfg.Safe {
		case SafeMustBeNil:
			require.Nil(t, safe)
		case SafeMustBePresent:
			require.NotNil(t, safe, "expected non-nil safe block")
			require.NotNil(t, latest, "expected non-nil latest for safe ordering check")
			require.NotNil(t, fin, "expected non-nil finalized for safe ordering check")
			require.LessOrEqual(t, fin.Number, safe.Number, "finalized should be at or before safe")
			require.LessOrEqual(t, safe.Number, latest.Number, "safe should be at or before latest")
			assertHeaderMatchesOracle(t, ctx, cfg.Oracle, "safe", safe)
		case SafeAny:
			if safe == nil {
				return
			}
			if latest != nil && fin != nil {
				require.LessOrEqual(t, fin.Number, safe.Number)
				require.LessOrEqual(t, safe.Number, latest.Number)
			}
			assertHeaderMatchesOracle(t, ctx, cfg.Oracle, "safe", safe)
		}
	})
}

func assertHeaderMatchesOracle(
	t *testing.T,
	ctx context.Context,
	oracle Oracle,
	role string,
	h *protocol.BlockHeader,
) {
	t.Helper()
	if h == nil {
		return
	}
	gt, err := oracle.BlockHeaderByNumber(ctx, h.Number)
	require.NoError(t, err, "oracle BlockHeaderByNumber for %s at %d", role, h.Number)
	require.NotNil(t, gt, "ground truth for %s at %d", role, h.Number)
	require.Equal(t, h.Hash, gt.Hash, "hash %s", role)
	require.Equal(t, h.ParentHash, gt.ParentHash, "parent hash %s", role)
	if !h.Timestamp.IsZero() && !gt.Timestamp.IsZero() {
		// Node and tracker may differ by rounding; 2s is generous for integration.
		d := h.Timestamp.Sub(gt.Timestamp)
		if d < 0 {
			d = -d
		}
		require.LessOrEqual(t, d, 2*time.Second, "timestamp %s", role)
	}
}

func headersOrderedByNumber(t *testing.T, a, b *protocol.BlockHeader, what string) {
	t.Helper()
	if a == nil || b == nil {
		return
	}
	require.LessOrEqual(t, a.Number, b.Number, "%s: first header number should be <= second", what)
}
