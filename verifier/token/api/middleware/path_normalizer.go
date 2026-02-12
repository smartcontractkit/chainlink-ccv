package middleware

// VerificationsPathNormalizer normalizes the /verifications endpoint path.
// Query parameters are stripped to avoid cardinality explosion in metrics.
// It returns the path as-is and always tracks it.
func VerificationsPathNormalizer(path string) (string, bool) {
	// Strip query parameters to avoid cardinality explosion
	// Since we only have /v1/verifications endpoint, we just return the path as-is
	// Gin already strips query params from c.Request.URL.Path
	return path, true
}
