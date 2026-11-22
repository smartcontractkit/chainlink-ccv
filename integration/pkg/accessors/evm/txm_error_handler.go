package evm

import (
	"context"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/types"
)

type deterministicTxErrorHandler struct{}

func (deterministicTxErrorHandler) HandleError(
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
	logger.Sugared(lggr).Warnw("Discarded transaction rejected on its first broadcast; reusing its nonce",
		"txID", tx.ID, "nonce", *tx.Nonce, "error", txErr)
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
