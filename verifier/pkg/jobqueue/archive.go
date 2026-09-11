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

// failureCategorySQL maps an archived row onto the bounded failure vocabulary at read time.
//
// R1 allows either persisting a category or defining a stable mapping; this is the mapping, so
// the inventory needs no schema change. Every input it reads (last_error, retry_deadline,
// completed_at) already exists on the archive tables.
//
// Retry-window expiry is decided by the timestamps rather than the error text: a job archived
// because its deadline passed carries whatever error last failed it, which on its own is
// indistinguishable from the same error on a job archived for another reason.
//
// The vocabulary is closed. Anything unmatched is "unknown" rather than a new label, so the
// metric's cardinality is fixed no matter what an error string says. TestArchiveFailureCategory
// pins each branch against seeded rows.
const failureCategorySQL = `CASE
	WHEN completed_at >= retry_deadline THEN 'retry_window_expired'
	WHEN last_error ILIKE '%%policy hook rejected%%' THEN 'policy_rejected'
	WHEN last_error ILIKE '%%unmarshal%%'
	  OR last_error ILIKE '%%deserialize%%'
	  OR last_error ILIKE '%%unsupported message version%%'
	  OR last_error ILIKE '%%receipt blobs list is empty%%'
	  OR last_error ILIKE '%%verification task is nil%%'
	  OR last_error ILIKE '%%sender cannot be empty or zero%%'
	  OR last_error ILIKE '%%receiver cannot be empty%%'
	  OR last_error ILIKE '%%invalid receipt structure%%'
	  OR last_error ILIKE '%%failed to parse receipt structure%%'
	  OR last_error ILIKE '%%failed to convert messageid to bytes32%%'
	  OR last_error ILIKE '%%neither verifier nor default executor blob found%%'
	  OR (last_error ILIKE '%%source chain selector%%' AND last_error ILIKE '%%not configured%%')
	  THEN 'validation_error'
	WHEN '%s' = 'ccv_storage_writer_jobs' THEN 'storage_failure'
	ELSE 'unknown'
END`

type archiveKey struct{ chain, category string }

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
	category := fmt.Sprintf(failureCategorySQL, q.tableName)
	query := fmt.Sprintf(`SELECT chain_selector::text, %s AS failure_category, COUNT(*),
		COUNT(*) FILTER (WHERE completed_at <= NOW() - $2::interval),
		GREATEST(0, EXTRACT(EPOCH FROM NOW() - MIN(completed_at)))::double precision
		FROM %s WHERE owner_id = $1 AND status = 'failed'
		GROUP BY chain_selector, %s`, category, q.archiveName, category)
	warningAge := fmt.Sprintf("%f seconds", (ArchiveRetention - ArchiveWarningLead).Seconds())
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
