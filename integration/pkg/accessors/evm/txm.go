package evm

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	evmclient "github.com/smartcontractkit/chainlink-evm/pkg/client"
	evmconfig "github.com/smartcontractkit/chainlink-evm/pkg/config"
	"github.com/smartcontractkit/chainlink-evm/pkg/gas"
	evmkeys "github.com/smartcontractkit/chainlink-evm/pkg/keys"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/clientwrappers"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/storage"
	"github.com/smartcontractkit/chainlink-evm/pkg/txmgr"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
)

// txmV2 is chainlink-evm's TXM v2 plus a handle on the store it keeps transactions in.
//
// The store is the reason this exists. TXM v2 holds transactions, attempts, and receipts in memory
// and chainlink-evm ships no durable alternative, so a restart leaves the new process with no
// record of what the old one had in flight. Recovering that record needs a way to put a transaction
// back into the store at a known nonce, and txmgr.NewTxmV2 builds the store internally and never
// exposes it (chainlink-evm pkg/txmgr/builder.go).
//
// So newTxmV2 assembles the same objects that builder does, from the same exported constructors,
// and keeps the store reference. It is a fork of upstream's builder and will drift if that builder
// changes; TestNewTxmV2MatchesUpstreamBuilder pins the parts that matter. The intended end state is
// for NewTxmV2 to accept a store manager, after which this file goes away.
type txmV2 struct {
	txmgr.TxManager

	// store is the same InMemoryStoreManager the TXM writes through, held so
	// recoverOrphanedTransactions can seed nonces the TXM has no record of.
	store *storage.InMemoryStoreManager
	// emptyTxGasLimit is the gas limit seeded transactions are created with, matching what TXM v2
	// uses for the empty transactions it creates itself to fill nonce gaps.
	emptyTxGasLimit uint64
}

// newTxmV2 mirrors txmgr.NewTxmV2 for the configuration standalone CCV runs: forwarders disabled,
// dual broadcast off, log poller absent. Those branches are omitted rather than reproduced, so this
// is smaller than upstream's builder and fails loudly if the config ever turns one of them on.
func newTxmV2(
	lggr logger.Logger,
	cfg evmconfig.EVM,
	chainClient evmclient.Client,
	chainKeystore evmkeys.ChainStore,
	estimator gas.EvmFeeEstimator,
) (*txmV2, error) {
	if cfg.Transactions().ForwardersEnabled() {
		return nil, fmt.Errorf("EVM forwarders are not supported by standalone CCV")
	}
	txmV2Cfg := cfg.Transactions().TransactionManagerV2()
	if dual := txmV2Cfg.DualBroadcast(); dual != nil && *dual {
		return nil, fmt.Errorf("EVM dual broadcast is not supported by standalone CCV")
	}
	if txmV2Cfg.BlockTime() == nil {
		return nil, fmt.Errorf("EVM transaction manager requires a block time")
	}

	chainID := chainClient.ConfiguredChainID()
	feeCfg := txmgr.NewEvmTxmFeeConfig(cfg.GasEstimator())
	gasCfg := cfg.GasEstimator()

	// AutoPurge drives the stuck transaction detector. Without it TXM never replaces a transaction
	// that the chain has stopped making progress on, so an underpriced attempt can hold its address
	// indefinitely. newChainlinkEVMConfig enables it; a nil detector here would silently drop that.
	var stuckTxDetector txm.StuckTxDetector
	if autoPurge := cfg.Transactions().AutoPurge(); autoPurge.Enabled() {
		var detectionURL string
		if u := autoPurge.DetectionApiUrl(); u != nil {
			detectionURL = u.String()
		}
		if autoPurge.Threshold() == nil {
			return nil, fmt.Errorf("EVM auto purge is enabled but has no stuck transaction threshold")
		}
		stuckTxDetector = txm.NewStuckTxDetector(lggr, cfg.ChainType(), txm.StuckTxDetectorConfig{
			BlockTime:             *txmV2Cfg.BlockTime(),
			StuckTxBlockThreshold: *autoPurge.Threshold(),
			DetectionURL:          detectionURL,
		})
	}

	readMultiNode := txmV2Cfg.ReadRequestsToMultipleNodes() != nil && *txmV2Cfg.ReadRequestsToMultipleNodes()
	wrappedClient, err := clientwrappers.NewChainClient(lggr, chainClient, readMultiNode)
	if err != nil {
		return nil, fmt.Errorf("failed to create EVM TXM chain client wrapper: %w", err)
	}

	emptyTxGasLimit := gasCfg.LimitTransfer()
	attemptBuilder := txm.NewAttemptBuilder(feeCfg.PriceMaxKey, estimator, chainKeystore, emptyTxGasLimit, false)
	store := storage.NewInMemoryStoreManager(lggr, chainID)
	metrics := txm.NewTxmMetrics(lggr, chainID)

	inner := txm.NewTxm(
		lggr,
		chainID,
		wrappedClient,
		attemptBuilder,
		store,
		stuckTxDetector,
		txm.Config{
			EIP1559:   feeCfg.EIP1559DynamicFees(),
			BlockTime: *txmV2Cfg.BlockTime(),
			//nolint:gosec // G115: mirrors upstream's cast in pkg/txmgr/builder.go
			RetryBlockThreshold: uint16(feeCfg.BumpThreshold()),
			EmptyTxLimitDefault: emptyTxGasLimit,
		},
		chainKeystore,
		nil, // No error handler: that is dual broadcast's, which is rejected above.
		metrics,
	)

	orchestrator := txm.NewTxmOrchestrator[common.Hash, *evmtypes.Head](
		lggr,
		chainID,
		inner,
		store,
		nil, // Forwarder manager, disabled above.
		chainKeystore,
		attemptBuilder,
	)

	return &txmV2{TxManager: orchestrator, store: store, emptyTxGasLimit: emptyTxGasLimit}, nil
}

// orphanedNonces reports the nonces an address has in the mempool that this process did not put
// there. The pending nonce counts transactions the chain has accepted but not mined; the latest
// nonce counts only mined ones. Any difference is transactions in flight.
//
// Called once, immediately after the TXM starts and before it has broadcast anything, so a
// difference can only have come from a previous run of this process. It is not a valid check later:
// in steady state the same difference is just this TXM's own in-flight work.
func orphanedNonces(ctx context.Context, chainClient evmclient.Client, address common.Address) (latest, pending uint64, err error) {
	pending, err = chainClient.PendingNonceAt(ctx, address)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read pending nonce for %s: %w", address, err)
	}
	latest, err = chainClient.NonceAt(ctx, address, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read latest nonce for %s: %w", address, err)
	}
	return latest, pending, nil
}

// seedOrphanedNonce puts a transaction into the store at a nonce the TXM has no record of, so its
// normal broadcast loop starts driving that nonce to completion.
//
// The contents of the original transaction are gone with the process that created it, and there is
// no portable way to read them back: recovering them would need the mempool contents, which public
// RPC providers do not expose. So this seeds an empty transaction, which chainlink-evm creates with
// IsPurgeable set. That makes the attempt builder price it as a purge attempt and makes the backfill
// loop rebroadcast it every tick with a bumped fee, escalating until it displaces the original.
// Displacing rather than completing the original is the point: the executor re-drives the message
// from on-chain state, so what matters is that the nonce stops blocking everything behind it.
//
// The first attempts may be rejected as "replacement transaction underpriced", because the original
// transaction's fee is unknown and the replacement has to beat it. chainlink-evm classifies that
// error as retryable, so the escalation converges rather than stalling.
func (t *txmV2) seedOrphanedNonce(ctx context.Context, address common.Address, nonce uint64) error {
	if _, err := t.store.CreateEmptyUnconfirmedTransaction(ctx, address, nonce, t.emptyTxGasLimit); err != nil {
		return fmt.Errorf("failed to seed recovery transaction at nonce %d for %s: %w", nonce, address, err)
	}
	return nil
}

// nonceRange is the inclusive-exclusive span of orphaned nonces, as a slice for iteration.
func nonceRange(latest, pending uint64) []uint64 {
	if pending <= latest {
		return nil
	}
	nonces := make([]uint64, 0, pending-latest)
	for n := latest; n < pending; n++ {
		nonces = append(nonces, n)
	}
	return nonces
}
