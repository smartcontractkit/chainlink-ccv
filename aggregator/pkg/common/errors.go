package common

import "errors"

var ErrNotFound = errors.New("not found")

// ErrTooManyRecords is returned when a query matches more rows than its fixed maximum.
var ErrTooManyRecords = errors.New("too many records")
