package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var (
	_ protocol.CCVNodeDataWriter  = &CCVWriter{}
	_ protocol.VerifierResultsAPI = &CCVReader{}
)

type CCVWriter struct {
	lggr                      logger.Logger
	verifierResolverAddresses map[protocol.ChainSelector]protocol.UnknownAddress
	storage                   CCVStorage
}

func NewCCVWriter(
	lggr logger.Logger,
	verifierResolverAddresses map[protocol.ChainSelector]protocol.UnknownAddress,
	storage CCVStorage,
) *CCVWriter {
	return &CCVWriter{
		lggr:                      lggr,
		verifierResolverAddresses: verifierResolverAddresses,
		storage:                   storage,
	}
}

func (a *CCVWriter) WriteCCVNodeData(
	ctx context.Context,
	ccvDataList []protocol.VerifierNodeResult,
) ([]protocol.WriteResult, error) {
	results := make([]protocol.WriteResult, len(ccvDataList))

	// Pre-populate results with input data
	for i, ccvData := range ccvDataList {
		results[i] = protocol.WriteResult{
			Input:     ccvData,
			Status:    protocol.WriteSuccess,
			Error:     nil,
			Retryable: false,
		}
	}

	entries := make([]Entry, len(ccvDataList))
	for i, ccvData := range ccvDataList {
		source, dest := a.addresses(ccvData.Message)
		entries[i] = Entry{
			Value:                 ccvData,
			VerifierSourceAddress: source,
			VerifierDestAddress:   dest,
			Timestamp:             time.Now(),
		}
	}

	err := a.storage.Set(ctx, entries)
	if err != nil {
		// If the entire batch failed, mark all as failed (retryable)
		for i := range results {
			results[i].Status = protocol.WriteFailure
			results[i].Error = err
			results[i].Retryable = true // Database errors are typically retryable
		}
		return results, err
	}

	return results, nil
}

func (a *CCVWriter) addresses(message protocol.Message) (protocol.UnknownAddress, protocol.UnknownAddress) {
	var ok bool
	var source, dest protocol.UnknownAddress
	source, ok = a.verifierResolverAddresses[message.SourceChainSelector]
	if !ok {
		a.lggr.Errorw("missing verifier address for source chain selector", "chainSelector", message.SourceChainSelector)
		source = protocol.UnknownAddress{}
	}
	dest, ok = a.verifierResolverAddresses[message.DestChainSelector]
	if !ok {
		a.lggr.Errorw("missing verifier address for dest chain selector", "chainSelector", message.DestChainSelector)
		dest = protocol.UnknownAddress{}
	}
	return source, dest
}

type CCVReader struct {
	storage CCVStorage
}

func NewCCVReader(
	storage CCVStorage,
) *CCVReader {
	return &CCVReader{
		storage: storage,
	}
}

func (a *CCVReader) GetVerifications(
	ctx context.Context,
	messageIDs []protocol.Bytes32,
) (map[protocol.Bytes32]protocol.VerifierResult, error) {
	storageOutput, err := a.storage.Get(ctx, messageIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get verifications from storage: %w", err)
	}

	results := make(map[protocol.Bytes32]protocol.VerifierResult)
	for msgID, entry := range storageOutput {
		results[msgID] = protocol.VerifierResult{
			MessageID:              entry.Value.MessageID,
			Message:                entry.Value.Message,
			MessageCCVAddresses:    entry.Value.CCVAddresses,
			MessageExecutorAddress: entry.Value.ExecutorAddress,
			CCVData:                entry.Value.Signature,
			Timestamp:              entry.Timestamp,
			VerifierSourceAddress:  entry.VerifierSourceAddress,
			VerifierDestAddress:    entry.VerifierDestAddress,
		}
	}
	return results, nil
}
