package evm

import (
	"context"
	"fmt"
	"time"

	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
)

// Block progression and reorg primitives for anvil-backed EVM chains.
//
// A real (non-anvil) RPC will pass the compile-time check but
// SupportManualBlockProgress / SupportReorgs return false at runtime.

var (
	_ cciptestinterfaces.ProgressableChain = (*CCIP17EVM)(nil)
	_ cciptestinterfaces.ReorgableChain    = (*CCIP17EVM)(nil)
	_ cciptestinterfaces.MineHoldableChain = (*CCIP17EVM)(nil)
)

// SupportMineHold reports whether the node exposes anvil's mining controls. anvil_getAutomine
// answering at all is the signal: a node that reports the setting also accepts anvil_setAutomine,
// anvil_setIntervalMining and anvil_mine. Unlike SupportManualBlockProgress this does not care what
// the current value is - devenv starts anvil with -b 1, which is interval mining, so automine reads
// as false there even though every control below works.
func (m *CCIP17EVM) SupportMineHold(ctx context.Context) bool {
	var automine bool
	if err := m.ethClient.Client().CallContext(ctx, &automine, "anvil_getAutomine"); err != nil {
		m.logger.Debug().Err(err).Msg("anvil_getAutomine not supported; mine hold disabled")
		return false
	}
	return true
}

// HoldMining stops block production. Both controls are needed: anvil started with -b runs interval
// mining, which keeps producing blocks no matter what automine is set to, and a node started
// without -b mines on every transaction.
func (m *CCIP17EVM) HoldMining(ctx context.Context) error {
	var result any
	if err := m.ethClient.Client().CallContext(ctx, &result, "anvil_setIntervalMining", 0); err != nil {
		return fmt.Errorf("anvil_setIntervalMining(0): %w", err)
	}
	if err := m.ethClient.Client().CallContext(ctx, &result, "anvil_setAutomine", false); err != nil {
		return fmt.Errorf("anvil_setAutomine(false): %w", err)
	}
	m.logger.Debug().Msg("Held block production")
	return nil
}

// ResumeMining restarts block production. Anvil mines whatever is queued in the mempool on the
// first block after this returns.
func (m *CCIP17EVM) ResumeMining(ctx context.Context, interval time.Duration) error {
	var result any
	if interval <= 0 {
		if err := m.ethClient.Client().CallContext(ctx, &result, "anvil_setAutomine", true); err != nil {
			return fmt.Errorf("anvil_setAutomine(true): %w", err)
		}
		m.logger.Debug().Msg("Resumed block production with automining")
		return nil
	}
	seconds := uint64(interval.Round(time.Second) / time.Second)
	if seconds == 0 {
		seconds = 1
	}
	if err := m.ethClient.Client().CallContext(ctx, &result, "anvil_setIntervalMining", seconds); err != nil {
		return fmt.Errorf("anvil_setIntervalMining(%d): %w", seconds, err)
	}
	m.logger.Debug().Uint64("intervalSeconds", seconds).Msg("Resumed block production with interval mining")
	return nil
}

// MineBlocks mines count blocks in one anvil_mine call with a zero inter-block interval, so the
// head moves but block timestamps do not.
func (m *CCIP17EVM) MineBlocks(ctx context.Context, count uint64) error {
	if count == 0 {
		return nil
	}
	var result any
	if err := m.ethClient.Client().CallContext(ctx, &result, "anvil_mine",
		hexutil.Uint64(count), hexutil.Uint64(0)); err != nil {
		return fmt.Errorf("anvil_mine(%d): %w", count, err)
	}
	m.logger.Debug().Uint64("blocks", count).Msg("Mined blocks")
	return nil
}

// PendingAndLatestNonce reports an address's mempool and mined nonce. A pending nonce above the
// latest means transactions have been accepted but not included, which is what a test watches for
// when it needs a transaction held in flight.
func (m *CCIP17EVM) PendingAndLatestNonce(ctx context.Context, address string) (pending, latest uint64, err error) {
	addr := gethcommon.HexToAddress(address)
	pending, err = m.ethClient.PendingNonceAt(ctx, addr)
	if err != nil {
		return 0, 0, fmt.Errorf("pending nonce for %s: %w", address, err)
	}
	latest, err = m.ethClient.NonceAt(ctx, addr, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("latest nonce for %s: %w", address, err)
	}
	return pending, latest, nil
}

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
