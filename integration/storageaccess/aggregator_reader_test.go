package storageaccess

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	msgdiscoverypb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-discovery/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

func TestReadCCVData_advances_since_when_dropping_nil_verifier_result(t *testing.T) {
	t.Parallel()
	lggr := logger.Test(t)
	initialSince := int64(0)
	mockDiscovery := mocks.NewMockMessageDiscoveryClient(t)
	mockDiscovery.EXPECT().GetMessagesSince(mock.Anything, mock.Anything, mock.Anything).Return(
		&msgdiscoverypb.GetMessagesSinceResponse{
			Results: []*msgdiscoverypb.VerifierResultWithSequence{
				{Sequence: 1, VerifierResult: nil},
			},
		},
		nil,
	).Once()
	mockVerifier := mocks.NewMockVerifierClient(t)
	reader := &AggregatorReader{
		client:                 mockVerifier,
		messageDiscoveryClient: mockDiscovery,
		lggr:                   lggr,
	}
	reader.SetSinceValue(initialSince)
	defer reader.Close()

	results, err := reader.ReadCCVData(context.Background())
	require.NoError(t, err)
	require.Empty(t, results)
	require.Equal(t, int64(2), reader.GetSinceValue(), "since must advance past dropped message so indexer does not get stuck")
}

func TestReadCCVData_advances_since_when_dropping_invalid_verifier_result(t *testing.T) {
	t.Parallel()
	lggr := logger.Test(t)
	initialSince := int64(5)
	mockDiscovery := mocks.NewMockMessageDiscoveryClient(t)
	mockDiscovery.EXPECT().GetMessagesSince(mock.Anything, mock.Anything, mock.Anything).Return(
		&msgdiscoverypb.GetMessagesSinceResponse{
			Results: []*msgdiscoverypb.VerifierResultWithSequence{
				{Sequence: 5, VerifierResult: &verifierpb.VerifierResult{Message: nil}},
			},
		},
		nil,
	).Once()
	mockVerifier := mocks.NewMockVerifierClient(t)
	reader := &AggregatorReader{
		client:                 mockVerifier,
		messageDiscoveryClient: mockDiscovery,
		lggr:                   lggr,
	}
	reader.SetSinceValue(initialSince)
	defer reader.Close()

	results, err := reader.ReadCCVData(context.Background())
	require.NoError(t, err)
	require.Empty(t, results)
	require.Equal(t, int64(6), reader.GetSinceValue(), "since must advance past corrupt message so indexer does not get stuck")
}

func TestReadCCVData_advances_since_and_returns_valid_only_when_some_results_corrupt(t *testing.T) {
	t.Parallel()
	lggr := logger.Test(t)
	initialSince := int64(10)
	validProto := minimalValidVerifierResultProto(t)
	mockDiscovery := mocks.NewMockMessageDiscoveryClient(t)
	mockDiscovery.EXPECT().GetMessagesSince(mock.Anything, mock.Anything, mock.Anything).Return(
		&msgdiscoverypb.GetMessagesSinceResponse{
			Results: []*msgdiscoverypb.VerifierResultWithSequence{
				{Sequence: 10, VerifierResult: validProto},
				{Sequence: 11, VerifierResult: nil},
				{Sequence: 12, VerifierResult: &verifierpb.VerifierResult{Message: nil}},
				{Sequence: 13, VerifierResult: validProto},
			},
		},
		nil,
	).Once()
	mockVerifier := mocks.NewMockVerifierClient(t)
	reader := &AggregatorReader{
		client:                 mockVerifier,
		messageDiscoveryClient: mockDiscovery,
		lggr:                   lggr,
	}
	reader.SetSinceValue(initialSince)
	defer reader.Close()

	results, err := reader.ReadCCVData(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Equal(t, int64(14), reader.GetSinceValue(), "since must advance to after last sequence")
}

func TestReadCCVData_does_not_advance_since_on_GetMessagesSince_error(t *testing.T) {
	t.Parallel()
	lggr := logger.Test(t)
	initialSince := int64(7)
	mockDiscovery := mocks.NewMockMessageDiscoveryClient(t)
	mockDiscovery.EXPECT().GetMessagesSince(mock.Anything, mock.Anything, mock.Anything).Return(
		nil, errors.New("network error"),
	).Once()
	mockVerifier := mocks.NewMockVerifierClient(t)
	reader := &AggregatorReader{
		client:                 mockVerifier,
		messageDiscoveryClient: mockDiscovery,
		lggr:                   lggr,
	}
	reader.SetSinceValue(initialSince)
	defer reader.Close()

	_, err := reader.ReadCCVData(context.Background())
	require.Error(t, err)
	require.Equal(t, int64(7), reader.GetSinceValue(), "since must not advance when RPC fails")
}

func TestReadCCVData_advances_since_for_empty_results(t *testing.T) {
	t.Parallel()
	lggr := logger.Test(t)
	initialSince := int64(3)
	mockDiscovery := mocks.NewMockMessageDiscoveryClient(t)
	mockDiscovery.EXPECT().GetMessagesSince(mock.Anything, mock.Anything, mock.Anything).Return(
		&msgdiscoverypb.GetMessagesSinceResponse{Results: nil},
		nil,
	).Once()
	mockVerifier := mocks.NewMockVerifierClient(t)
	reader := &AggregatorReader{
		client:                 mockVerifier,
		messageDiscoveryClient: mockDiscovery,
		lggr:                   lggr,
	}
	reader.SetSinceValue(initialSince)
	defer reader.Close()

	results, err := reader.ReadCCVData(context.Background())
	require.NoError(t, err)
	require.Empty(t, results)
	require.Equal(t, int64(3), reader.GetSinceValue(), "since unchanged when no results")
}

func minimalValidVerifierResultProto(t *testing.T) *verifierpb.VerifierResult {
	t.Helper()
	onRamp := make([]byte, 20)
	offRamp := make([]byte, 20)
	sender := make([]byte, 20)
	receiver := make([]byte, 20)
	msg := &verifierpb.Message{
		Version:              1,
		SourceChainSelector:  1,
		DestChainSelector:    2,
		SequenceNumber:       100,
		OnRampAddressLength:  20,
		OnRampAddress:        onRamp,
		OffRampAddressLength: 20,
		OffRampAddress:       offRamp,
		CcvAndExecutorHash:   make([]byte, 32),
		SenderLength:         20,
		Sender:               sender,
		ReceiverLength:       20,
		Receiver:             receiver,
		DestBlobLength:       0,
		TokenTransferLength:  0,
		DataLength:           0,
	}
	return &verifierpb.VerifierResult{
		Message:                msg,
		MessageCcvAddresses:    [][]byte{make([]byte, 20)},
		MessageExecutorAddress: make([]byte, 20),
		CcvData:                []byte{},
		Metadata: &verifierpb.VerifierResultMetadata{
			Timestamp:             0,
			VerifierSourceAddress: make([]byte, 20),
			VerifierDestAddress:   make([]byte, 20),
		},
	}
}
