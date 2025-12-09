package storage

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

var (
	_ protocol.CCVNodeDataWriter  = &AttestationCCVWriter{}
	_ protocol.VerifierResultsAPI = &AttestationCCVReader{}
)

type AttestationCCVWriter struct {
	verifierSourceAddress protocol.UnknownAddress
	verifierDestAddress   protocol.UnknownAddress
	storage               *InMemory
}

func NewAttestationCCVWriter(
	verifierSourceAddress protocol.UnknownAddress,
	verifierDestAddress protocol.UnknownAddress,
	storage *InMemory,
) *AttestationCCVWriter {
	return &AttestationCCVWriter{
		verifierSourceAddress: verifierSourceAddress,
		verifierDestAddress:   verifierDestAddress,
		storage:               storage,
	}
}

func (a *AttestationCCVWriter) WriteCCVNodeData(
	ctx context.Context,
	ccvDataList []protocol.VerifierNodeResult,
) error {
	entries := make([]Entry, len(ccvDataList))
	for i, ccvData := range ccvDataList {
		entries[i] = Entry{
			value:                 ccvData,
			verifierSourceAddress: a.verifierSourceAddress,
			verifierDestAddress:   a.verifierDestAddress,
			timestamp:             time.Now(),
		}
	}
	return a.storage.Set(ctx, entries)
}

type AttestationCCVReader struct {
	storage *InMemory
}

func NewAttestationCCVReader(
	storage *InMemory,
) *AttestationCCVReader {
	return &AttestationCCVReader{
		storage: storage,
	}
}

func (a *AttestationCCVReader) GetVerifications(
	ctx context.Context,
	messageIDs []protocol.Bytes32,
) (map[protocol.Bytes32]protocol.VerifierResult, error) {
	storageOutput := a.storage.Get(ctx, messageIDs)

	results := make(map[protocol.Bytes32]protocol.VerifierResult)
	for msgID, entry := range storageOutput {
		results[msgID] = protocol.VerifierResult{
			MessageID:              entry.value.MessageID,
			Message:                entry.value.Message,
			MessageCCVAddresses:    entry.value.CCVAddresses,
			MessageExecutorAddress: entry.value.ExecutorAddress,
			CCVData:                entry.value.Signature,
			Timestamp:              entry.timestamp,
			VerifierSourceAddress:  entry.verifierSourceAddress,
			VerifierDestAddress:    entry.verifierDestAddress,
		}
	}
	return results, nil
}
