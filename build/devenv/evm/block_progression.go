package evm

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
)

// Block progression and reorg primitives for anvil-backed EVM chains.
//
// A real (non-anvil) RPC will pass the compile-time check but
// SupportManualBlockProgress / SupportReorgs return false at runtime.

var (
	_ cciptestinterfaces.ProgressableChain = (*CCIP17EVM)(nil)
	_ cciptestinterfaces.ReorgableChain    = (*CCIP17EVM)(nil)
)

// SupportManualBlockProgress returns true iff the node accepts anvil's
// evm_mine and has automining enabled (so txs sent by tests still land).
func (m *CCIP17EVM) SupportManualBlockProgress(ctx context.Context) bool {
	var automine bool
	if err := m.ethClient.Client().CallContext(ctx, &automine, "anvil_getAutomine"); err != nil {
		m.logger.Debug().Err(err).Msg("anvil_getAutomine not supported; manual block progression disabled")
		return false
	}
	return automine
}

// AdvanceBlocks mines numBlocks blocks and then briefly sleeps to let
// downstream pollers observe the new head. A non-positive numBlocks is a
// no-op. Each block is mined in its own RPC call - matching anvil's
// per-block semantics and avoiding a single oversized batch.
func (m *CCIP17EVM) AdvanceBlocks(ctx context.Context, numBlocks int) error {
	if numBlocks <= 0 {
		return nil
	}
	for i := range numBlocks {
		var result any
		if err := m.ethClient.Client().CallContext(ctx, &result, "evm_mine"); err != nil {
			return fmt.Errorf("advance blocks: evm_mine on block %d/%d: %w", i+1, numBlocks, err)
		}
	}
	m.logger.Debug().Int("numBlocks", numBlocks).Msg("Advanced blocks")
	return nil
}

// SupportReorgs probes evm_snapshot; a nil error implies evm_revert is
// also available. The probe snapshot is intentionally not reverted -
// anvil's snapshot store is unbounded and cheap, and reverting would
// drop any blocks mined between the probe and the caller's use.
func (m *CCIP17EVM) SupportReorgs(ctx context.Context) bool {
	var snapshotID string
	if err := m.ethClient.Client().CallContext(ctx, &snapshotID, "evm_snapshot"); err != nil {
		m.logger.Debug().Err(err).Msg("evm_snapshot not supported; reorgs disabled")
		return false
	}
	return true
}

// Snapshot captures the current chain state for later Revert.
func (m *CCIP17EVM) Snapshot(ctx context.Context) (cciptestinterfaces.SnapshotID, error) {
	var snapshotID string
	if err := m.ethClient.Client().CallContext(ctx, &snapshotID, "evm_snapshot"); err != nil {
		return nil, fmt.Errorf("evm_snapshot: %w", err)
	}
	m.logger.Debug().Str("snapshotID", snapshotID).Msg("Created snapshot")
	return cciptestinterfaces.SnapshotID([]byte(snapshotID)), nil
}

// Revert restores the chain to the given snapshot. Anvil invalidates the
// snapshot (and any taken after it) on success, so callers must take a
// fresh snapshot if they need to revert again.
func (m *CCIP17EVM) Revert(ctx context.Context, id cciptestinterfaces.SnapshotID) error {
	if len(id) == 0 {
		return fmt.Errorf("revert: empty snapshot id")
	}
	var ok bool
	if err := m.ethClient.Client().CallContext(ctx, &ok, "evm_revert", string(id)); err != nil {
		return fmt.Errorf("evm_revert %s: %w", id, err)
	}
	if !ok {
		return fmt.Errorf("evm_revert %s returned false (snapshot expired or already reverted)", id)
	}
	m.logger.Debug().Str("snapshotID", string(id)).Msg("Reverted to snapshot")
	return nil
}
