package jobqueue

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
)

const (
	ArchiveRetention          = 30 * 24 * time.Hour
	ArchiveWarningLead        = 7 * 24 * time.Hour
	ArchiveCollectionInterval = time.Minute
)

// FailureCategory classifies only at archival, so changing error text later cannot
// reinterpret historical inventory. Retry expiry is assigned by SQL before this mapping.
func FailureCategory(queue string, err error) string {
	if err == nil {
		return "unknown"
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "policy hook rejected"):
		return "policy_rejected"
	case strings.Contains(s, "unmarshal"), strings.Contains(s, "deserialize"),
		strings.Contains(s, "unsupported message version"), strings.Contains(s, "receipt blobs list is empty"),
		strings.Contains(s, "verification task is nil"), strings.Contains(s, "sender cannot be empty or zero"),
		strings.Contains(s, "receiver cannot be empty"), strings.Contains(s, "invalid receipt structure"),
		strings.Contains(s, "failed to parse receipt structure"), strings.Contains(s, "failed to convert messageid to bytes32"),
		strings.Contains(s, "neither verifier nor default executor blob found"),
		strings.Contains(s, "source chain selector") && strings.Contains(s, "not configured"):
		return "validation_error"
	case queue == "ccv_storage_writer_jobs":
		return "storage_failure"
	default:
		return "unknown"
	}
}

type archiveKey struct { chain, category string }

type archiveSnapshot struct {
	Count     int64
	Expiring  int64
	OldestAge float64
}

type archiveMetrics struct {
	mu          sync.Mutex
	previous    map[archiveKey]archiveSnapshot
	count       metric.Int64Gauge
	expiring    metric.Int64Gauge
	age         metric.Float64Gauge
	success     metric.Int64Gauge
	lastSuccess metric.Float64Gauge
}

func newArchiveMetrics() (*archiveMetrics, error) {
	m := &archiveMetrics{previous: make(map[archiveKey]archiveSnapshot)}
	var err error
	meter := beholder.GetMeter()
	if m.count, err = meter.Int64Gauge("verifier_archive_failed_jobs"); err != nil {
		return nil, err
	}
	if m.expiring, err = meter.Int64Gauge("verifier_archive_expiring_jobs"); err != nil {
		return nil, err
	}
	if m.age, err = meter.Float64Gauge("verifier_archive_oldest_age_seconds"); err != nil {
		return nil, err
	}
	if m.success, err = meter.Int64Gauge("verifier_archive_collection_success"); err != nil {
		return nil, err
	}
	if m.lastSuccess, err = meter.Float64Gauge("verifier_archive_last_success_timestamp"); err != nil {
		return nil, err
	}
	return m, nil
}

func (q *PostgresJobQueue[T]) archiveSnapshot(ctx context.Context) (map[archiveKey]archiveSnapshot, error) {
	query := fmt.Sprintf(`SELECT chain_selector::text, failure_category, COUNT(*),
		COUNT(*) FILTER (WHERE completed_at <= NOW() - $2::interval),
		GREATEST(0, EXTRACT(EPOCH FROM NOW() - MIN(completed_at)))::double precision
		FROM %s WHERE owner_id = $1 AND status = 'failed'
		GROUP BY chain_selector, failure_category`, q.archiveName)
	warningAge := fmt.Sprintf("%f seconds", (ArchiveRetention-ArchiveWarningLead).Seconds())
	rows, err := q.ds.QueryContext(ctx, query, q.ownerID, warningAge)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	result := make(map[archiveKey]archiveSnapshot)
	for rows.Next() {
		var key archiveKey
		var value archiveSnapshot
		if err := rows.Scan(&key.chain, &key.category, &value.Count, &value.Expiring, &value.OldestAge); err != nil {
			return nil, err
		}
		result[key] = value
	}
	return result, rows.Err()
}

// CollectArchiveMetrics preserves the last good inventory on failure, and explicitly
// clears disappeared groups after successful collection (reschedule or cleanup).
func (q *PostgresJobQueue[T]) CollectArchiveMetrics(ctx context.Context) error {
	m := q.archiveMetrics
	m.mu.Lock()
	defer m.mu.Unlock()
	queue := strings.TrimSuffix(strings.TrimPrefix(q.tableName, "ccv_"), "_jobs")
	queue = strings.ReplaceAll(queue, "_", "-")
	base := []attribute.KeyValue{attribute.String("queue", queue), attribute.String("verifier_id", q.ownerID)}
	values, err := q.archiveSnapshot(ctx)
	if err != nil {
		m.success.Record(ctx, 0, metric.WithAttributes(base...))
		return err
	}
	for key := range m.previous {
		if _, ok := values[key]; !ok {
			values[key] = archiveSnapshot{}
		}
	}
	next := make(map[archiveKey]archiveSnapshot)
	for key, value := range values {
		attrs := append(append([]attribute.KeyValue(nil), base...), attribute.String("source_chain", key.chain), attribute.String("reason", key.category))
		m.count.Record(ctx, value.Count, metric.WithAttributes(attrs...))
		m.expiring.Record(ctx, value.Expiring, metric.WithAttributes(attrs...))
		m.age.Record(ctx, value.OldestAge, metric.WithAttributes(attrs...))
		if value.Count > 0 {
			next[key] = value
		}
	}
	m.previous = next
	m.success.Record(ctx, 1, metric.WithAttributes(base...))
	m.lastSuccess.Record(ctx, float64(time.Now().Unix()), metric.WithAttributes(base...))
	return nil
}
