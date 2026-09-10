package recovery

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type Metrics struct {
	attrs         []attribute.KeyValue
	operations    metric.Int64Gauge
	blocks        metric.Int64Gauge
	auditFailures metric.Int64Counter
	collection    metric.Int64Gauge
	lastSuccess   metric.Float64Gauge
}

func NewMetrics(owner, chain string) (*Metrics, error) {
	m := &Metrics{attrs: []attribute.KeyValue{attribute.String("verifier_id", owner), attribute.String("source_chain", chain)}}
	meter := beholder.GetMeter()
	var err error
	if m.operations, err = meter.Int64Gauge("verifier_recovery_operations"); err != nil {
		return nil, err
	}
	if m.blocks, err = meter.Int64Gauge("verifier_recovery_remaining_blocks"); err != nil {
		return nil, err
	}
	if m.auditFailures, err = meter.Int64Counter("verifier_recovery_audit_failures_total"); err != nil {
		return nil, err
	}
	if m.collection, err = meter.Int64Gauge("verifier_recovery_collection_success"); err != nil {
		return nil, err
	}
	if m.lastSuccess, err = meter.Float64Gauge("verifier_recovery_last_success_timestamp"); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Metrics) AuditFailure(ctx context.Context) { m.auditFailures.Add(ctx, 1, metric.WithAttributes(m.attrs...)) }

func (s *Store) CollectMetrics(ctx context.Context, owner, chain string, m *Metrics) error {
	rows, err := s.ds.QueryContext(ctx, `SELECT state, COUNT(*), LEAST(9223372036854775807,
		COALESCE(SUM(GREATEST(0, to_block-next_block+1)),0))::bigint
		FROM ccv_recovery_operations WHERE owner_id=$1 AND chain_selector=$2 GROUP BY state`, owner, chain)
	if err != nil {
		m.collection.Record(ctx, 0, metric.WithAttributes(m.attrs...))
		return err
	}
	defer func() { _ = rows.Close() }()
	counts, blocks := make(map[string]int64), make(map[string]int64)
	for rows.Next() {
		var state string
		var count, remaining int64
		if err := rows.Scan(&state, &count, &remaining); err != nil {
			m.collection.Record(ctx, 0, metric.WithAttributes(m.attrs...))
			return err
		}
		counts[state], blocks[state] = count, remaining
	}
	if err := rows.Err(); err != nil {
		m.collection.Record(ctx, 0, metric.WithAttributes(m.attrs...))
		return err
	}
	for _, state := range []string{"accepted", "running", "completed", "cancelled", "failed", "blocked"} {
		attrs := append(append([]attribute.KeyValue(nil), m.attrs...), attribute.String("state", state))
		m.operations.Record(ctx, counts[state], metric.WithAttributes(attrs...))
		m.blocks.Record(ctx, blocks[state], metric.WithAttributes(attrs...))
	}
	m.collection.Record(ctx, 1, metric.WithAttributes(m.attrs...))
	m.lastSuccess.Record(ctx, float64(time.Now().Unix()), metric.WithAttributes(m.attrs...))
	return nil
}
