package common

import "errors"

// ErrAggregationChannelFull is returned when the aggregation channel is full.
var ErrAggregationChannelFull = errors.New("aggregation channel is full")
