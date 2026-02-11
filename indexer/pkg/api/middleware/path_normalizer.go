package middleware

import (
	"strings"
)

// RemoveMessageIDFromPath normalizes verifierresults paths by replacing message IDs with a placeholder.
// Always returns true to track all endpoints in the indexer.
func RemoveMessageIDFromPath(path string) (string, bool) {
	if strings.Contains(path, "/verifierresults/") {
		// Normalize to a canonical path with a placeholder for the message ID.
		return "/verifierresults/:messageID", true
	}

	return path, true
}
