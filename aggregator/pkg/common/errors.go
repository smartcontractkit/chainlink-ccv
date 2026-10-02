package common

import "errors"

// ErrAggregationChannelFull is returned when the aggregation channel is full.
var ErrAggregationChannelFull = errors.New("aggregation channel is full")

var ErrNotFound = errors.New("not found")

// ErrTooManyRecords is returned when a query matches more rows than its fixed maximum.
var ErrTooManyRecords = errors.New("too many records")

var ErrShuttingDown = errors.New("channel manager is shutting down")
