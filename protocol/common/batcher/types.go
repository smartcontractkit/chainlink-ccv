package batcher

// BatchResult carries a batch of items with an optional error.
// This generic type is used to pass batches of data between processing phases.
type BatchResult[T any] struct {
	// Items contains the batch of elements
	Items []T
	// Error indicates if there was an error producing this batch
	Error error
}
