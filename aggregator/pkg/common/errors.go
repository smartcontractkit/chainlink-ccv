package common

import "errors"

var (
	// ErrAggregationChannelFull is returned when the aggregation channel is full.
	ErrAggregationChannelFull = errors.New("aggregation channel is full")
)
