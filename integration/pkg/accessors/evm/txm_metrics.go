package evm

import (
	"context"
	"math/big"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm"
)

type discardedTransactionMetrics interface {
	IncrementDiscardedTransactions(context.Context)
	IncrementLifecycleFailure(context.Context, txm.LifecycleFailureStage)
}

// CCVTxmMetrics combines the standard TXM metrics with CCV discard observability.
type CCVTxmMetrics interface {
	txm.Metrics
	// IncrementDiscardedTransactions records a deterministic rejection discarded by CCV.
	IncrementDiscardedTransactions(context.Context)
}

type ccvTxmMetrics struct {
	txm.Metrics
	discarded metric.Int64Counter
	chainID   *big.Int
}

// NewCCVTxmMetrics creates the standard TXM metrics plus CCV discard observability.
func NewCCVTxmMetrics(lggr logger.Logger, chainID *big.Int) CCVTxmMetrics {
	discarded, err := beholder.GetMeter().Int64Counter(
		"executor_txm_discarded_transactions_total",
		metric.WithDescription("Transactions discarded after a deterministic first-broadcast gas rejection"),
	)
	if err != nil {
		lggr.Errorw("Failed to initialize discarded transaction metric; discards will only be logged", "err", err)
	}
	return &ccvTxmMetrics{
		Metrics:   txm.NewTxmMetrics(lggr, chainID),
		discarded: discarded,
		chainID:   chainID,
	}
}

func (m *ccvTxmMetrics) IncrementDiscardedTransactions(ctx context.Context) {
	if m.discarded == nil {
		return
	}
	m.discarded.Add(ctx, 1, metric.WithAttributes(attribute.String("chainID", m.chainID.String())))
}
