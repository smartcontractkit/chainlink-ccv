package evm

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/types"
)

type pendingNonceClient interface {
	PendingNonceAt(context.Context, common.Address) (uint64, error)
}

type deterministicTxErrorHandler struct {
	client   pendingNonceClient
	getNonce func(common.Address) uint64
	metrics  discardedTransactionMetrics
}

func (h *deterministicTxErrorHandler) HandleError(
	ctx context.Context,
	lggr logger.Logger,
	tx *types.Transaction,
	txErr error,
	txStore txm.TxStore,
	setNonce func(common.Address, uint64),
) (bool, error) {
	if tx.AttemptCount != 1 || tx.IsPurgeable || !isDeterministicGasRejection(txErr) {
		return false, nil
	}
	if tx.Nonce == nil {
		return false, nil
	}

	pendingNonce, err := h.client.PendingNonceAt(ctx, tx.FromAddress)
	if err != nil {
		return false, fmt.Errorf("failed to verify rejected transaction nonce: %w", err)
	}
	if pendingNonce > *tx.Nonce {
		return false, nil
	}

	nonceRewound := h.getNonce(tx.FromAddress) == *tx.Nonce+1
	if nonceRewound {
		if err := txStore.MarkTxFatal(ctx, tx, tx.FromAddress); err != nil {
			return false, err
		}
		setNonce(tx.FromAddress, *tx.Nonce)
	} else {
		if err := txStore.MarkUnconfirmedTransactionPurgeable(ctx, *tx.Nonce, tx.FromAddress); err != nil {
			return false, err
		}
	}
	if h.metrics != nil {
		h.metrics.IncrementLifecycleFailure(ctx, txm.StageBroadcast)
		h.metrics.IncrementDiscardedTransactions(ctx)
	}
	var messageIDs []string
	meta, err := tx.GetMeta()
	if err != nil {
		logger.Sugared(lggr).Warnw("Failed to read metadata for discarded transaction", "txID", tx.ID, "error", err)
	} else if meta != nil {
		messageIDs = meta.MessageIDs
	}
	logger.Sugared(lggr).Warnw("Discarded transaction after deterministic first-broadcast rejection",
		"txID", tx.ID, "nonce", *tx.Nonce, "nonceRewound", nonceRewound, "messageIDs", messageIDs, "error", txErr)
	return true, nil
}

func isDeterministicGasRejection(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "intrinsic gas too low") ||
		strings.Contains(msg, "insufficient gas for floor data gas cost") ||
		strings.Contains(msg, "intrinsic gas exceeds gas limit") ||
		strings.Contains(msg, "is insufficient of intrinsic gas required")
}
