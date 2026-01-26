package v1

import (
	"fmt"
	"time"
)

// parseTime attempts to parse a time string in either RFC3339 format or as a unix epoch time in milliseconds.
func parseTime(t string) (int64, error) {
	if t == "" {
		return 0, nil
	}

	// Try to parse as RFC3339
	parsedTime, err := time.Parse(time.RFC3339, t)
	if err == nil {
		return parsedTime.UnixMilli(), nil
	}

	// Try to parse as unix epoch time in milliseconds
	var epochMillis int64
	_, err = fmt.Sscanf(t, "%d", &epochMillis)
	if err != nil {
		return 0, fmt.Errorf("invalid time format: %s", t)
	}

	return epochMillis, nil
}
