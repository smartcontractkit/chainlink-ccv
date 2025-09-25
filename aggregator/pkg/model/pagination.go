package model

// PaginatedAggregatedReportsResponse represents a paginated response from QueryAggregatedReports.
type PaginatedAggregatedReportsResponse struct {
	// Reports contains the aggregated reports for the current page.
	Reports []*CommitAggregatedReport
	// HasMore indicates whether there are more pages available.
	HasMore bool
	// LastSeqNum is the sequence number of the last record in this page.
	// Used for generating the next pagination token. Nil if no records returned.
	LastSeqNum *int64
}
