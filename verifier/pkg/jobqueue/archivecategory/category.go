// Package archivecategory holds the read-time failure classification shared by the verifier's
// archive-inventory metrics and the job-queue CLI. It is a leaf package because
// verifier/pkg/jobqueue's tests import cli/jobqueue, which also needs this expression.
package archivecategory

import "fmt"

// expr maps an archived row onto a bounded failure vocabulary at read time, so the inventory
// needs no schema change; expiry is decided by timestamps, not error text, and unmatched rows
// are "unknown" so cardinality stays fixed. Pinned by TestArchiveFailureCategory.
const expr = `CASE
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

// SQL returns the classification expression bound to the queue's active table name, which
// disambiguates storage-writer rows.
func SQL(activeTableName string) string {
	return fmt.Sprintf(expr, activeTableName)
}
