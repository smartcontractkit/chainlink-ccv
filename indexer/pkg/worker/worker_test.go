package worker

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// TestExecute_StorageError ensures Execute returns an error when storage GetCCVData fails.
func TestExecute_StorageError(t *testing.T) {
	lggr := logger.Test(t)

	ms := mocks.NewMockIndexerStorage(t)
	// Simulate storage error on GetCCVData
	ms.On("GetCCVData", mock.Anything, mock.Anything).Return(nil, errors.New("db failure"))

	msg := protocol.VerifierResult{MessageCCVAddresses: []protocol.UnknownAddress{mustAddr(t, "0x1111111111111111111111111111111111111111")}}
	task := &Task{storage: ms, message: msg, logger: lggr}

	_, err := Execute(context.Background(), task)
	require.Error(t, err)
}

// TestExecute_NoMissingVerifiers_NoBatchInsert verifies Execute doesn't call BatchInsertCCVData
// when the storage already contains the necessary verifier results.
func TestExecute_NoMissingVerifiers_NoBatchInsert(t *testing.T) {
	lggr := logger.Test(t)

	ms := mocks.NewMockIndexerStorage(t)
	addr := mustAddr(t, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	// Storage returns existing verifier matching the message CCV
	vr := common.VerifierResultWithMetadata{VerifierResult: protocol.VerifierResult{VerifierSourceAddress: addr}, Metadata: common.VerifierResultMetadata{}}
	ms.On("GetCCVData", mock.Anything, mock.Anything).Return([]common.VerifierResultWithMetadata{vr}, nil)

	// Ensure BatchInsertCCVData is not called
	ms.On("BatchInsertCCVData", mock.Anything, mock.Anything).Return(nil).Maybe()

	msg := protocol.VerifierResult{MessageCCVAddresses: []protocol.UnknownAddress{addr}}
	// Use a real logger
	task := &Task{storage: ms, message: msg, logger: lggr}

	res, err := Execute(context.Background(), task)
	require.NoError(t, err)
	require.Equal(t, 0, res.SuccessfulVerifications)
	require.Equal(t, 0, res.UnknownCCVs)
	require.Equal(t, 0, res.UnavailableCCVs)

	// Assert BatchInsertCCVData was not invoked
	ms.AssertNotCalled(t, "BatchInsertCCVData", mock.Anything, mock.Anything)
}

// TestExecute_MissingUnknownCCVs verifies Execute correctly counts unknown CCV addresses
// when no verifiers are present in the registry.
func TestExecute_MissingUnknownCCVs(t *testing.T) {
	lggr := logger.Test(t)

	ms := mocks.NewMockIndexerStorage(t)
	// Storage returns no existing verifications
	ms.On("GetCCVData", mock.Anything, mock.Anything).Return([]common.VerifierResultWithMetadata{}, nil)

	addr1 := mustAddr(t, "0x1111111111111111111111111111111111111111")
	addr2 := mustAddr(t, "0x2222222222222222222222222222222222222222")
	msg := protocol.VerifierResult{MessageCCVAddresses: []protocol.UnknownAddress{addr1, addr2}}
	reg := registry.NewVerifierRegistry()
	task := &Task{storage: ms, message: msg, registry: reg, logger: lggr}

	res, err := Execute(context.Background(), task)
	require.NoError(t, err)
	// Since registry has no readers, loadVerifierReaders will treat verifiers as missing/unknown
	require.Equal(t, 2, res.UnknownCCVs)
	require.Equal(t, 0, res.SuccessfulVerifications)
	require.Equal(t, 0, res.UnavailableCCVs)
}
