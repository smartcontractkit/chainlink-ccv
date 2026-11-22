package evm

import (
	"context"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/types"
)

type deterministicTxErrorHandler struct {
	metrics discardedTransactionMetrics
}

func (h deterministicTxErrorHandler) HandleError(
	ctx context.Context,
	lggr logger.Logger,
	tx *types.Transaction,
	txErr error,
	txStore txm.TxStore,
	setNonce func(common.Address, uint64),
) (bool, error) {
	if tx.AttemptCount != 1 || !isDeterministicGasRejection(txErr) {
		return false, nil
	}
	if tx.Nonce == nil {
		return false, nil
	}
	if err := txStore.MarkTxFatal(ctx, tx, tx.FromAddress); err != nil {
		return false, err
	}
	setNonce(tx.FromAddress, *tx.Nonce)
	if h.metrics != nil {
		h.metrics.IncrementDiscardedTransactions(ctx)
	}
	var messageIDs []string
	meta, err := tx.GetMeta()
	if err != nil {
		logger.Sugared(lggr).Warnw("Failed to read metadata for discarded transaction", "txID", tx.ID, "error", err)
	} else if meta != nil {
		messageIDs = meta.MessageIDs
	}
	logger.Sugared(lggr).Warnw("Discarded transaction rejected on its first broadcast; reusing its nonce",
		"txID", tx.ID, "nonce", *tx.Nonce, "messageIDs", messageIDs, "error", txErr)
	return true, nil
}

func isDeterministicGasRejection(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "intrinsic gas too low") ||
		strings.Contains(msg, "insufficient gas for floor data gas cost")
}
