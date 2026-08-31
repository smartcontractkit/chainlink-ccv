package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
)

// DBLoadSample is a point-in-time read of the server's cumulative work counters.
type DBLoadSample struct {
	At time.Time
	// Statements maps a shortened, normalized query text to its call count.
	Statements map[string]int64
	TotalCalls int64
	// XactCommit counts transactions, not statements. Publish wraps several inserts in
	// one transaction, so this undercounts work; it is here to show that the change
	// added no transaction, not to measure load.
	XactCommit int64
	// IndexScans maps "table.index" to its scan count. It separates the pending index
	// from the stale index, and it counts a scan even when the query matches no rows.
	IndexScans map[string]int64
	SeqScans   map[string]int64
}

// DBLoadDelta is the work done between two samples.
type DBLoadDelta struct {
	Elapsed        time.Duration
	Calls          int64
	CallsPerSecond float64
	ByStatement    map[string]int64
	ByIndex        map[string]int64
	SeqScans       map[string]int64
	XactCommit     int64
}

// DBLoadRecorder samples the server's counters over a dedicated connection.
//
// It works in deltas and never calls any pg_stat reset function, so several tests can
// share one container without destroying each other's measurements.
type DBLoadRecorder struct {
	conn   *sqlx.Conn
	tables []string
}

// NewDBLoadRecorder opens a dedicated connection for sampling. Statistics snapshots and
// session settings are per connection, so it must not share the pool with the code under
// measurement.
func NewDBLoadRecorder(tb testing.TB, dbConn *sqlx.DB, tables ...string) *DBLoadRecorder {
	tb.Helper()

	conn, err := dbConn.Connx(context.Background())
	require.NoError(tb, err, "failed to check out a recorder connection")
	tb.Cleanup(func() { _ = conn.Close() })

	return &DBLoadRecorder{conn: conn, tables: tables}
}

// Snapshot reads the counters as they stand now.
func (r *DBLoadRecorder) Snapshot(tb testing.TB) DBLoadSample {
	tb.Helper()
	ctx := context.Background()

	// Drop any statistics snapshot this connection is still holding.
	_, err := r.conn.ExecContext(ctx, "SELECT pg_stat_clear_snapshot()")
	require.NoError(tb, err)

	sample := DBLoadSample{
		At:         time.Now(),
		Statements: make(map[string]int64),
		IndexScans: make(map[string]int64),
		SeqScans:   make(map[string]int64),
	}

	// The recorder's own queries are excluded, so measuring does not show up as load.
	rows, err := r.conn.QueryxContext(ctx, `
		SELECT left(regexp_replace(s.query, '\s+', ' ', 'g'), 120) AS q, s.calls
		FROM pg_stat_statements s
		JOIN pg_database d ON d.oid = s.dbid
		WHERE d.datname = current_database()
		  AND s.query NOT ILIKE '%pg_stat%'`)
	require.NoError(tb, err)
	for rows.Next() {
		var q string
		var calls int64
		require.NoError(tb, rows.Scan(&q, &calls))
		sample.Statements[strings.TrimSpace(q)] += calls
		sample.TotalCalls += calls
	}
	require.NoError(tb, rows.Err())
	require.NoError(tb, rows.Close())

	idxRows, err := r.conn.QueryxContext(ctx, `
		SELECT relname, indexrelname, idx_scan
		FROM pg_stat_user_indexes WHERE relname = ANY($1)`, sqlxArray(r.tables))
	require.NoError(tb, err)
	for idxRows.Next() {
		var table, index string
		var scans sql.NullInt64
		require.NoError(tb, idxRows.Scan(&table, &index, &scans))
		sample.IndexScans[table+"."+index] = scans.Int64
	}
	require.NoError(tb, idxRows.Err())
	require.NoError(tb, idxRows.Close())

	seqRows, err := r.conn.QueryxContext(ctx, `
		SELECT relname, seq_scan FROM pg_stat_user_tables WHERE relname = ANY($1)`, sqlxArray(r.tables))
	require.NoError(tb, err)
	for seqRows.Next() {
		var table string
		var scans sql.NullInt64
		require.NoError(tb, seqRows.Scan(&table, &scans))
		sample.SeqScans[table] = scans.Int64
	}
	require.NoError(tb, seqRows.Err())
	require.NoError(tb, seqRows.Close())

	require.NoError(tb, r.conn.GetContext(ctx, &sample.XactCommit,
		"SELECT xact_commit FROM pg_stat_database WHERE datname = current_database()"))

	return sample
}

// Measure samples, runs fn, samples again, and returns the difference. fn should block
// for the whole measurement window.
func (r *DBLoadRecorder) Measure(tb testing.TB, fn func()) DBLoadDelta {
	tb.Helper()

	before := r.Snapshot(tb)
	fn()
	after := r.Snapshot(tb)

	delta := DBLoadDelta{
		Elapsed:     after.At.Sub(before.At),
		Calls:       after.TotalCalls - before.TotalCalls,
		XactCommit:  after.XactCommit - before.XactCommit,
		ByStatement: make(map[string]int64),
		ByIndex:     make(map[string]int64),
		SeqScans:    make(map[string]int64),
	}
	for q, calls := range after.Statements {
		if d := calls - before.Statements[q]; d > 0 {
			delta.ByStatement[q] = d
		}
	}
	for k, scans := range after.IndexScans {
		if d := scans - before.IndexScans[k]; d > 0 {
			delta.ByIndex[k] = d
		}
	}
	for k, scans := range after.SeqScans {
		if d := scans - before.SeqScans[k]; d > 0 {
			delta.SeqScans[k] = d
		}
	}
	if delta.Elapsed > 0 {
		delta.CallsPerSecond = float64(delta.Calls) / delta.Elapsed.Seconds()
	}
	return delta
}

// Log prints the per-statement breakdown, heaviest first.
func (d DBLoadDelta) Log(tb testing.TB, label string) {
	tb.Helper()

	type row struct {
		q     string
		calls int64
	}
	rows := make([]row, 0, len(d.ByStatement))
	for q, calls := range d.ByStatement {
		rows = append(rows, row{q, calls})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].calls > rows[j].calls })

	var b strings.Builder
	fmt.Fprintf(&b, "\n=== DB load: %s ===\n", label)
	fmt.Fprintf(&b, "  window %.2fs  statements %d  (%.2f/s)  commits %d\n",
		d.Elapsed.Seconds(), d.Calls, d.CallsPerSecond, d.XactCommit)
	for _, r := range rows {
		fmt.Fprintf(&b, "  %8d  %s\n", r.calls, r.q)
	}
	for k, v := range d.ByIndex {
		fmt.Fprintf(&b, "  index scan %8d  %s\n", v, k)
	}
	for k, v := range d.SeqScans {
		fmt.Fprintf(&b, "  seq scan   %8d  %s\n", v, k)
	}
	tb.Log(b.String())
}

// StatementsPerJob is the load metric for scenarios that do real work. Raw statement rate
// is the wrong measure there, because a consumer that does more work in the same window
// legitimately issues more statements.
func StatementsPerJob(d DBLoadDelta, jobs int64) float64 {
	if jobs <= 0 {
		return 0
	}
	return float64(d.Calls) / float64(jobs)
}

// CallsRatio reports how many times more statements per second the first delta used.
// Tests assert on this rather than on absolute counts, so they hold on any machine.
func CallsRatio(before, after DBLoadDelta) float64 {
	if after.CallsPerSecond <= 0 {
		if before.CallsPerSecond <= 0 {
			return 1
		}
		// The measured side issued nothing at all, which is better than any finite ratio.
		return float64(before.Calls) + 1
	}
	return before.CallsPerSecond / after.CallsPerSecond
}

// sqlxArray renders a Go string slice as a Postgres array literal for = ANY($1).
func sqlxArray(values []string) string {
	return "{" + strings.Join(values, ",") + "}"
}
