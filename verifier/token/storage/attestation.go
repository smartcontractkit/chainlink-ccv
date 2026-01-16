package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var (
	_ protocol.CCVNodeDataWriter  = &AttestationCCVWriter{}
	_ protocol.VerifierResultsAPI = &AttestationCCVReader{}
)

type AttestationCCVWriter struct {
	lggr              logger.Logger
	verifierAddresses map[protocol.ChainSelector]protocol.UnknownAddress
	storage           CCVStorage
}

func NewAttestationCCVWriter(
	lggr logger.Logger,
	verifierAddresses map[protocol.ChainSelector]protocol.UnknownAddress,
	storage CCVStorage,
) *AttestationCCVWriter {
	return &AttestationCCVWriter{
		lggr:              lggr,
		verifierAddresses: verifierAddresses,
		storage:           storage,
	}
}

func (a *AttestationCCVWriter) WriteCCVNodeData(
	ctx context.Context,
	ccvDataList []protocol.VerifierNodeResult,
) error {
	entries := make([]Entry, len(ccvDataList))
	for i, ccvData := range ccvDataList {
		source, dest := a.addresses(ccvData.Message)
		entries[i] = Entry{
			value:                 ccvData,
			verifierSourceAddress: source,
			verifierDestAddress:   dest,
			timestamp:             time.Now(),
		}
	}
	return a.storage.Set(ctx, entries)
}

func (a *AttestationCCVWriter) addresses(message protocol.Message) (protocol.UnknownAddress, protocol.UnknownAddress) {
	var ok bool
	var source, dest protocol.UnknownAddress
	source, ok = a.verifierAddresses[message.SourceChainSelector]
	if !ok {
		a.lggr.Errorw("missing verifier address for source chain selector", "chainSelector", message.SourceChainSelector)
		source = protocol.UnknownAddress{}
	}
	dest, ok = a.verifierAddresses[message.DestChainSelector]
	if !ok {
		a.lggr.Errorw("missing verifier address for dest chain selector", "chainSelector", message.DestChainSelector)
		dest = protocol.UnknownAddress{}
	}
	return source, dest
}

type AttestationCCVReader struct {
	storage CCVStorage
}

func NewAttestationCCVReader(
	storage CCVStorage,
) *AttestationCCVReader {
	return &AttestationCCVReader{
		storage: storage,
	}
}

func (a *AttestationCCVReader) GetVerifications(
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
