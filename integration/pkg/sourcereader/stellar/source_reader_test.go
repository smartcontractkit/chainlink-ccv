package stellar

import (
	"context"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	protocolrpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestNewSourceReaderWithClient(t *testing.T) {
	lggr, err := logger.New()
	require.NoError(t, err)

	t.Run("returns error when client is nil", func(t *testing.T) {
		reader, err := NewSourceReaderWithClient(nil, "CADDR", "transfer", lggr)
		require.Error(t, err)
		require.Nil(t, reader)
		assert.Contains(t, err.Error(), "rpc client is required")
	})

	t.Run("returns error when logger is nil", func(t *testing.T) {
		mockClient := mocks.NewMockRPCClient(t)
		reader, err := NewSourceReaderWithClient(mockClient, "CADDR", "transfer", nil)
		require.Error(t, err)
		require.Nil(t, reader)
		assert.Contains(t, err.Error(), "logger is required")
	})

	t.Run("returns error when ccip onramp address is empty", func(t *testing.T) {
		mockClient := mocks.NewMockRPCClient(t)
		reader, err := NewSourceReaderWithClient(mockClient, "", "transfer", lggr)
		require.Error(t, err)
		require.Nil(t, reader)
		assert.Contains(t, err.Error(), "ccip onramp address is required")
	})

	t.Run("returns error when ccip message sent topic is empty", func(t *testing.T) {
		mockClient := mocks.NewMockRPCClient(t)
		reader, err := NewSourceReaderWithClient(mockClient, "CADDR", "", lggr)
		require.Error(t, err)
		require.Nil(t, reader)
		assert.Contains(t, err.Error(), "ccip message sent topic is required")
	})

	t.Run("creates reader with mock client", func(t *testing.T) {
		mockClient := mocks.NewMockRPCClient(t)

		reader, err := NewSourceReaderWithClient(mockClient, "CADDR", "transfer", lggr)
		require.NoError(t, err)
		require.NotNil(t, reader)
		assert.Equal(t, "CADDR", reader.ccipOnrampAddress)
		assert.Equal(t, "transfer", reader.ccipMessageSentTopic)
	})
}

func TestLatestAndFinalizedBlock(t *testing.T) {
	lggr, err := logger.New()
	require.NoError(t, err)

	// Helper to create a valid base64-encoded ledger header
	createLedgerHeaderB64 := func(prevHash xdr.Hash) string {
		hdr := xdr.LedgerHeader{
			LedgerVersion:      22,
			PreviousLedgerHash: prevHash,
			ScpValue:           xdr.StellarValue{},
			TxSetResultHash:    xdr.Hash{},
			BucketListHash:     xdr.Hash{},
			LedgerSeq:          12345,
			TotalCoins:         1000000000,
			FeePool:            100000,
			InflationSeq:       0,
			IdPool:             1000,
			BaseFee:            100,
			BaseReserve:        5000000,
			MaxTxSetSize:       100,
		}
		xdrBytes, _ := hdr.MarshalBinary()
		return base64.StdEncoding.EncodeToString(xdrBytes)
	}

	t.Run("returns latest and finalized block on success", func(t *testing.T) {
		mockClient := mocks.NewMockRPCClient(t)

		prevHash := xdr.Hash{0x01, 0x02, 0x03}
		headerB64 := createLedgerHeaderB64(prevHash)

		mockClient.On("GetLatestLedger", mock.Anything).Return(
			protocolrpc.GetLatestLedgerResponse{
				Hash:            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
				Sequence:        12345,
				LedgerCloseTime: 1704067200, // 2024-01-01 00:00:00 UTC
				LedgerHeader:    headerB64,
			},
			nil,
		).Once()

		reader, err := NewSourceReaderWithClient(mockClient, "CADDR", "transfer", lggr)
		require.NoError(t, err)

		latest, finalized, err := reader.LatestAndFinalizedBlock(context.Background())
		require.NoError(t, err)
		require.NotNil(t, latest)
		require.NotNil(t, finalized)

		// Stellar has instant finality, so latest == finalized
		assert.Equal(t, uint64(12345), latest.Number)
		assert.Equal(t, uint64(12345), finalized.Number)
		assert.Equal(t, latest.Number, finalized.Number)
		assert.Equal(t, latest.Hash, finalized.Hash)
	})

	t.Run("returns error when GetLatestLedger fails", func(t *testing.T) {
		mockClient := mocks.NewMockRPCClient(t)

		mockClient.On("GetLatestLedger", mock.Anything).Return(
			protocolrpc.GetLatestLedgerResponse{},
			errors.New("rpc connection failed"),
		).Once()

		reader, err := NewSourceReaderWithClient(mockClient, "CADDR", "transfer", lggr)
		require.NoError(t, err)

		latest, finalized, err := reader.LatestAndFinalizedBlock(context.Background())
		require.Error(t, err)
		require.Nil(t, latest)
		require.Nil(t, finalized)
		assert.Contains(t, err.Error(), "failed to get latest ledger")
	})
}

func TestGetBlocksHeaders(t *testing.T) {
	lggr, err := logger.New()
	require.NoError(t, err)

	// Helper to create a valid base64-encoded ledger metadata (LedgerCloseMeta)
	// Using V0 which has simpler structure requirements
	createLedgerMetaB64 := func(seq uint32, prevHash xdr.Hash) string {
		hdr := xdr.LedgerHeader{
			LedgerVersion:      22,
			PreviousLedgerHash: prevHash,
			LedgerSeq:          xdr.Uint32(seq),
		}
		lcm := xdr.LedgerCloseMeta{
			V: 0,
			V0: &xdr.LedgerCloseMetaV0{
				LedgerHeader: xdr.LedgerHeaderHistoryEntry{
					Header: hdr,
				},
				TxSet: xdr.TransactionSet{},
			},
		}
		xdrBytes, _ := lcm.MarshalBinary()
		return base64.StdEncoding.EncodeToString(xdrBytes)
	}

	t.Run("returns headers for single ledger", func(t *testing.T) {
		mockClient := mocks.NewMockRPCClient(t)

		prevHash := xdr.Hash{0xaa, 0xbb, 0xcc}
		metaB64 := createLedgerMetaB64(100, prevHash)

		mockClient.On("GetLedgers", mock.Anything, mock.MatchedBy(func(req protocolrpc.GetLedgersRequest) bool {
			return req.StartLedger == 100 && req.Pagination.Limit == 1
		})).Return(
			protocolrpc.GetLedgersResponse{
				Ledgers: []protocolrpc.LedgerInfo{
					{
						Hash:            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
						Sequence:        100,
						LedgerCloseTime: 1704067200,
						LedgerMetadata:  metaB64,
					},
				},
			},
			nil,
		).Once()

		reader, err := NewSourceReaderWithClient(mockClient, "CADDR", "transfer", lggr)
		require.NoError(t, err)

		blockNumbers := []*big.Int{big.NewInt(100)}
		headers, err := reader.GetBlocksHeaders(context.Background(), blockNumbers)
		require.NoError(t, err)
		require.Len(t, headers, 1)

		// Find the header by the original key
		header, exists := headers[blockNumbers[0]]
		require.True(t, exists)
		assert.Equal(t, uint64(100), header.Number)
	})

	t.Run("returns headers for multiple ledgers", func(t *testing.T) {
		mockClient := mocks.NewMockRPCClient(t)

		// Set up expectations for both ledgers
		mockClient.On("GetLedgers", mock.Anything, mock.MatchedBy(func(req protocolrpc.GetLedgersRequest) bool {
			return req.StartLedger == 100
		})).Return(
			protocolrpc.GetLedgersResponse{
				Ledgers: []protocolrpc.LedgerInfo{
					{
						Hash:            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
						Sequence:        100,
						LedgerCloseTime: 1704067200,
						LedgerMetadata:  createLedgerMetaB64(100, xdr.Hash{0x01}),
					},
				},
			},
			nil,
		).Once()

		mockClient.On("GetLedgers", mock.Anything, mock.MatchedBy(func(req protocolrpc.GetLedgersRequest) bool {
			return req.StartLedger == 200
		})).Return(
			protocolrpc.GetLedgersResponse{
				Ledgers: []protocolrpc.LedgerInfo{
					{
						Hash:            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
						Sequence:        200,
						LedgerCloseTime: 1704153600,
						LedgerMetadata:  createLedgerMetaB64(200, xdr.Hash{0x02}),
					},
				},
			},
			nil,
		).Once()

		reader, err := NewSourceReaderWithClient(mockClient, "CADDR", "transfer", lggr)
		require.NoError(t, err)

		blockNumbers := []*big.Int{big.NewInt(100), big.NewInt(200)}
		headers, err := reader.GetBlocksHeaders(context.Background(), blockNumbers)
		require.NoError(t, err)
		require.Len(t, headers, 2)
	})

	t.Run("returns error when ledger not found", func(t *testing.T) {
		mockClient := mocks.NewMockRPCClient(t)

		mockClient.On("GetLedgers", mock.Anything, mock.Anything).Return(
			protocolrpc.GetLedgersResponse{
				Ledgers: []protocolrpc.LedgerInfo{}, // Empty response
			},
			nil,
		).Once()

		reader, err := NewSourceReaderWithClient(mockClient, "CADDR", "transfer", lggr)
		require.NoError(t, err)

		blockNumbers := []*big.Int{big.NewInt(999999999)}
		headers, err := reader.GetBlocksHeaders(context.Background(), blockNumbers)
		require.Error(t, err)
		require.Nil(t, headers)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("returns error when GetLedgers fails", func(t *testing.T) {
		mockClient := mocks.NewMockRPCClient(t)

		mockClient.On("GetLedgers", mock.Anything, mock.Anything).Return(
			protocolrpc.GetLedgersResponse{},
			errors.New("rpc timeout"),
		).Once()

		reader, err := NewSourceReaderWithClient(mockClient, "CADDR", "transfer", lggr)
		require.NoError(t, err)

		blockNumbers := []*big.Int{big.NewInt(100)}
		headers, err := reader.GetBlocksHeaders(context.Background(), blockNumbers)
		require.Error(t, err)
		require.Nil(t, headers)
		assert.Contains(t, err.Error(), "failed to get ledger")
	})

	t.Run("returns error when ledger sequence mismatch", func(t *testing.T) {
		mockClient := mocks.NewMockRPCClient(t)

		// Return a different sequence than requested
		mockClient.On("GetLedgers", mock.Anything, mock.Anything).Return(
			protocolrpc.GetLedgersResponse{
				Ledgers: []protocolrpc.LedgerInfo{
					{
						Hash:            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
						Sequence:        999, // Different from requested 100
						LedgerCloseTime: 1704067200,
						LedgerMetadata:  createLedgerMetaB64(999, xdr.Hash{0x01}),
					},
				},
			},
			nil,
		).Once()

		reader, err := NewSourceReaderWithClient(mockClient, "CADDR", "transfer", lggr)
		require.NoError(t, err)

		blockNumbers := []*big.Int{big.NewInt(100)}
		headers, err := reader.GetBlocksHeaders(context.Background(), blockNumbers)
		require.Error(t, err)
		require.Nil(t, headers)
		assert.Contains(t, err.Error(), "ledger seq mismatch")
	})

	t.Run("returns error when block number exceeds uint32 range", func(t *testing.T) {
		mockClient := mocks.NewMockRPCClient(t)

		reader, err := NewSourceReaderWithClient(mockClient, "CADDR", "transfer", lggr)
		require.NoError(t, err)

		// Create a number larger than uint32 max
		bigNumber := new(big.Int).SetUint64(1 << 33) // > MaxUint32
		blockNumbers := []*big.Int{bigNumber}
		headers, err := reader.GetBlocksHeaders(context.Background(), blockNumbers)
		require.Error(t, err)
		require.Nil(t, headers)
		assert.Contains(t, err.Error(), "exceeds uint32")
	})
}

func TestTransferEventStruct(t *testing.T) {
	t.Run("struct initialization", func(t *testing.T) {
		event := TransferEvent{
			From:            "GABC123...",
			To:              "GDEF456...",
			Amount:          nil,
			Ledger:          61068906,
			TransactionHash: "abc123def456",
		}

		assert.Equal(t, "GABC123...", event.From)
		assert.Equal(t, "GDEF456...", event.To)
		assert.Nil(t, event.Amount)
		assert.Equal(t, uint32(61068906), event.Ledger)
		assert.Equal(t, "abc123def456", event.TransactionHash)
	})
}
