package storage

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ common.IndexerStorage = (*Sink)(nil)

// Sink implements a chain-of-responsibility pattern for storage operations.
// For reads, it tries each storage in order (if read condition allows) until data is found.
// For writes, it writes to all storages in order (first storage written to first).
type Sink struct {
	storages []common.IndexerStorage
	lggr     logger.Logger
}

// NewSink creates a new storage sink with the provided storages.
// Each storage can have a read condition to control when it's used for reads.
// The order of storages determines the read and write priority:
// - Reads: Try first eligible storage, if not found try second, etc.
// - Writes: Write to first storage, then second, etc.
func NewSink(lggr logger.Logger, storages ...common.IndexerStorage) (*Sink, error) {
	if len(storages) == 0 {
		return nil, fmt.Errorf("at least one storage is required")
	}

	return &Sink{
		storages: storages,
		lggr:     lggr,
	}, nil
}

// GetCCVData tries to retrieve data from each storage in order until found.
// Returns the first successful result, or the last error if all storages fail.
func (d *Sink) GetCCVData(ctx context.Context, messageID protocol.Bytes32) ([]common.VerifierResultWithMetadata, error) {
	var lastErr error

	for i, storage := range d.storages {
		d.lggr.Debugw("Attempting to read from storage",
			"storageIndex", i,
			"messageID", messageID.String(),
		)

		data, err := storage.GetCCVData(ctx, messageID)
		if err == nil {
			d.lggr.Debugw("Successfully read from storage",
				"storageIndex", i,
				"messageID", messageID.String(),
				"dataCount", len(data),
			)
			return data, nil
		}

		// If it's not a "not found" error, log it as a warning
		if err != ErrCCVDataNotFound {
			d.lggr.Warnw("Error reading from storage",
				"storageIndex", i,
				"messageID", messageID.String(),
				"error", err,
			)
		} else {
			d.lggr.Debugw("Data not found in storage",
				"storageIndex", i,
				"messageID", messageID.String(),
			)
		}

		lastErr = err
	}

	// All eligible storages failed, return the last error
	return nil, lastErr
}

func (d *Sink) GetCCVDataSkipCache(ctx context.Context, messageID protocol.Bytes32) ([]common.VerifierResultWithMetadata, error) {
	var lastErr error

	storageLength := len(d.storages)
	for i, storage := range d.storages {
		if storageLength > 1 && i == 0 {
			d.lggr.Debugw("Skipping cache read", "storageIndex", i, "messageID", messageID.String())
			continue
		}

		d.lggr.Debugw("Attemptting to read from storage", "storageIndex", i, "messageID", messageID.String())

		data, err := storage.GetCCVData(ctx, messageID)
		if err == nil {
			d.lggr.Debugw("Successfully read from storage", "storageIndex", i, "messageID", messageID.String(), "dataCount", len(data))
			return data, nil
		}

		if err != ErrCCVDataNotFound {
			d.lggr.Warnw("Error reading from storage", "storageIndex", i, "messageID", messageID.String(), "error", err)
		} else {
			d.lggr.Debugw("Data not found in storage", "storageIndex", i, "messageID", messageID.String(), "error", err)
		}

		lastErr = err
	}

	return nil, lastErr
}

// QueryCCVData tries to retrieve data from each storage in order until successful.
// Returns the first successful result, or the last error if all storages fail.
// This method respects time-based read conditions by checking if the query time range
// overlaps with each storage's configured time range.
func (d *Sink) QueryCCVData(
	ctx context.Context,
	start, end int64,
	sourceChainSelectors, destChainSelectors []protocol.ChainSelector,
	limit, offset uint64,
) (map[string][]common.VerifierResultWithMetadata, error) {
	var lastErr error
	attemptedCount := 0

	for i, storage := range d.storages {
		attemptedCount++
		d.lggr.Debugw("Attempting to query from storage",
			"storageIndex", i,
			"start", start,
			"end", end,
			"limit", limit,
			"offset", offset,
		)

		data, err := storage.QueryCCVData(ctx, start, end, sourceChainSelectors, destChainSelectors, limit, offset)
		if err == ErrCCVDataNotFound || len(data) == 0 {
			d.lggr.Debugw("No data found in storage",
				"storageIndex", i,
				"start", start,
				"end", end,
			)

			lastErr = err
			continue
		}

		if err == nil && len(data) > 0 {
			d.lggr.Debugw("Successfully queried from storage",
				"storageIndex", i,
				"resultCount", len(data),
			)
			return data, nil
		}

		d.lggr.Warnw("Error querying from storage",
			"storageIndex", i,
			"error", err,
		)

		lastErr = err
	}

	// If we didn't attempt any storages, return a specific error
	if attemptedCount == 0 {
		return nil, fmt.Errorf("no storages eligible for read based on conditions (query time range: %d-%d)", start, end)
	}

	// All eligible storages failed, return the last error
	return nil, lastErr
}

// InsertCCVData writes data to all storages in order.
// If any storage fails (except duplicate errors), it continues to the next storage
// and returns an error at the end indicating which storages failed.
func (d *Sink) InsertCCVData(ctx context.Context, ccvData common.VerifierResultWithMetadata) error {
	var errs []error
	successCount := 0

	for i, storage := range d.storages {
		d.lggr.Debugw("Attempting to write to storage",
			"storageIndex", i,
			"messageID", ccvData.VerifierResult.MessageID.String(),
		)

		err := storage.InsertCCVData(ctx, ccvData)
		if err != nil {
			// If it's a duplicate error, log it as debug and continue
			if err == ErrDuplicateCCVData {
				d.lggr.Debugw("Duplicate data in storage (expected if syncing)",
					"storageIndex", i,
					"messageID", ccvData.VerifierResult.MessageID.String(),
				)
				// Don't count duplicates as errors since the data is already there
				successCount++
				continue
			}

			// For other errors, log as warning and track the error
			d.lggr.Warnw("Failed to write to storage",
				"storageIndex", i,
				"messageID", ccvData.VerifierResult.MessageID.String(),
				"error", err,
			)
			errs = append(errs, fmt.Errorf("storage[%d]: %w", i, err))
			continue
		}

		d.lggr.Debugw("Successfully wrote to storage",
			"storageIndex", i,
			"messageID", ccvData.VerifierResult.MessageID.String(),
		)
		successCount++
	}

	// If no storages succeeded, return an error
	if successCount == 0 {
		return fmt.Errorf("failed to write to any storage: %v", errs)
	}

	// If some storages failed, return an error but mention partial success
	if len(errs) > 0 {
		return fmt.Errorf("partial write failure (%d/%d succeeded): %v", successCount, len(d.storages), errs)
	}

	return nil
}

// batchWriteToStorages is a helper function that performs batch writes to all storages
// and handles error collection and logging. It returns an error if all storages fail
// or if some storages fail (with partial success indication).
func (d *Sink) batchWriteToStorages(
	ctx context.Context,
	batchSize int,
	operationName string,
	writeFunc func(context.Context, common.IndexerStorage) error,
) error {
	var errs []error
	successCount := 0

	for i, storage := range d.storages {
		logMsg := "Attempting batch write to storage"
		if operationName != "" {
			logMsg = fmt.Sprintf("Attempting batch write %s to storage", operationName)
		}
		d.lggr.Debugw(logMsg,
			"storageIndex", i,
			"batchSize", batchSize,
		)

		err := writeFunc(ctx, storage)
		if err != nil {
			logMsg = "Failed to batch write to storage"
			if operationName != "" {
				logMsg = fmt.Sprintf("Failed to batch write %s to storage", operationName)
			}
			d.lggr.Warnw(logMsg,
				"storageIndex", i,
				"batchSize", batchSize,
				"error", err,
			)
			errs = append(errs, fmt.Errorf("storage[%d]: %w", i, err))
			continue
		}

		logMsg = "Successfully batch wrote to storage"
		if operationName != "" {
			logMsg = fmt.Sprintf("Successfully batch wrote %s to storage", operationName)
		}
		d.lggr.Debugw(logMsg,
			"storageIndex", i,
			"batchSize", batchSize,
		)
		successCount++
	}

	// If no storages succeeded, return an error
	errMsg := "failed to batch write to any storage"
	if operationName != "" {
		errMsg = fmt.Sprintf("failed to batch write %s to any storage", operationName)
	}
	if successCount == 0 {
		return fmt.Errorf("%s: %v", errMsg, errs)
	}

	// If some storages failed, return an error but mention partial success
	if len(errs) > 0 {
		return fmt.Errorf("partial batch write failure (%d/%d succeeded): %v", successCount, len(d.storages), errs)
	}

	return nil
}

// BatchInsertCCVData writes multiple CCVData entries to all storages in order.
// If any storage fails (except duplicate errors), it continues to the next storage
// and returns an error at the end indicating which storages failed.
func (d *Sink) BatchInsertCCVData(ctx context.Context, ccvDataList []common.VerifierResultWithMetadata) error {
	if len(ccvDataList) == 0 {
		return nil
	}

	return d.batchWriteToStorages(ctx, len(ccvDataList), "BatchInsertCCVData", func(ctx context.Context, storage common.IndexerStorage) error {
		return storage.BatchInsertCCVData(ctx, ccvDataList)
	})
}

// InsertMessage writes a message to all storages in order.
func (d *Sink) InsertMessage(ctx context.Context, message common.MessageWithMetadata) error {
	var errs []error
	successCount := 0

	for i, storage := range d.storages {
		d.lggr.Debugw("Attempting to write message to storage",
			"storageIndex", i,
			"messageID", message.Message.MustMessageID().String(),
		)

		err := storage.InsertMessage(ctx, message)
		if err != nil {
			d.lggr.Warnw("Failed to write message to storage",
				"storageIndex", i,
				"messageID", message.Message.MustMessageID().String(),
				"error", err,
			)
			errs = append(errs, fmt.Errorf("storage[%d]: %w", i, err))
			continue
		}

		d.lggr.Debugw("Successfully wrote message to storage",
			"storageIndex", i,
			"messageID", message.Message.MustMessageID().String(),
		)
		successCount++
	}

	// If no storages succeeded, return an error
	if successCount == 0 {
		return fmt.Errorf("failed to write message to any storage: %v", errs)
	}

	// If some storages failed, return an error but mention partial success
	if len(errs) > 0 {
		return fmt.Errorf("partial write failure (%d/%d succeeded): %v", successCount, len(d.storages), errs)
	}

	return nil
}

// BatchInsertMessages writes multiple messages to all storages in order.
func (d *Sink) BatchInsertMessages(ctx context.Context, messages []common.MessageWithMetadata) error {
	if len(messages) == 0 {
		return nil
	}

	return d.batchWriteToStorages(ctx, len(messages), "BatchInsertMessages", func(ctx context.Context, storage common.IndexerStorage) error {
		return storage.BatchInsertMessages(ctx, messages)
	})
}

// UpdateMessageStatus updates the status of a message in all storages.
func (d *Sink) UpdateMessageStatus(ctx context.Context, messageID protocol.Bytes32, status common.MessageStatus, lastErr string) error {
	var errs []error
	successCount := 0

	for i, storage := range d.storages {
		d.lggr.Debugw("Attempting to update message status in storage",
			"storageIndex", i,
			"messageID", messageID.String(),
			"status", status.String(),
		)

		err := storage.UpdateMessageStatus(ctx, messageID, status, lastErr)
		if err != nil {
			d.lggr.Warnw("Failed to update message status in storage",
				"storageIndex", i,
				"messageID", messageID.String(),
				"error", err,
			)
			errs = append(errs, fmt.Errorf("storage[%d]: %w", i, err))
			continue
		}

		d.lggr.Debugw("Successfully updated message status in storage",
			"storageIndex", i,
			"messageID", messageID.String(),
		)
		successCount++
	}

	// If no storages succeeded, return an error
	if successCount == 0 {
		return fmt.Errorf("failed to update message status in any storage: %v", errs)
	}

	// If some storages failed, return an error but mention partial success
	if len(errs) > 0 {
		return fmt.Errorf("partial update failure (%d/%d succeeded): %v", successCount, len(d.storages), errs)
	}

	return nil
}

// Close closes all underlying storages that implement the Closer interface.
func (d *Sink) Close() error {
	var errs []error

	for i, storage := range d.storages {
		if closer, ok := storage.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				d.lggr.Warnw("Failed to close storage",
					"storageIndex", i,
					"error", err,
				)
				errs = append(errs, fmt.Errorf("storage[%d]: %w", i, err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to close some storages: %v", errs)
	}

	return nil
}
