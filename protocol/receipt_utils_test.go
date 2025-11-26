package protocol

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseReceiptStructure(t *testing.T) {
	tests := []struct {
		name              string
		receipts          []ReceiptWithBlob
		numCCVBlobs       int
		numTokenTransfers int
		expectedErr       bool
		expectedErrMsg    string
		validateResult    func(t *testing.T, result *ReceiptStructure)
	}{
		{
			name:              "empty receipts",
			receipts:          []ReceiptWithBlob{},
			numCCVBlobs:       0,
			numTokenTransfers: 0,
			expectedErr:       true,
			expectedErrMsg:    "no receipts provided",
		},
		{
			name: "only executor receipt - no CCVs or tokens",
			receipts: []ReceiptWithBlob{
				{
					Issuer:            UnknownAddress([]byte{0x01}),
					DestGasLimit:      100000,
					DestBytesOverhead: 50,
					Blob:              nil,
					ExtraArgs:         []byte{},
					FeeTokenAmount:    big.NewInt(1000),
				},
			},
			numCCVBlobs:       0,
			numTokenTransfers: 0,
			expectedErr:       false,
			validateResult: func(t *testing.T, result *ReceiptStructure) {
				assert.Len(t, result.CCVReceipts, 0)
				assert.Len(t, result.TokenReceipts, 0)
				assert.Len(t, result.CCVAddresses, 0)
				assert.Equal(t, UnknownAddress([]byte{0x01}), result.ExecutorAddress)
				assert.Equal(t, uint64(100000), result.ExecutorReceipt.DestGasLimit)
			},
		},
		{
			name: "single CCV with executor - no tokens",
			receipts: []ReceiptWithBlob{
				{
					Issuer:            UnknownAddress([]byte{0xCC, 0x01}),
					DestGasLimit:      50000,
					DestBytesOverhead: 20,
					Blob:              []byte{0xAA, 0xBB},
					ExtraArgs:         []byte{0x11},
					FeeTokenAmount:    big.NewInt(500),
				},
				{
					Issuer:            UnknownAddress([]byte{0xEE, 0x01}),
					DestGasLimit:      100000,
					DestBytesOverhead: 50,
					Blob:              nil,
					ExtraArgs:         []byte{0x22},
					FeeTokenAmount:    big.NewInt(1000),
				},
			},
			numCCVBlobs:       1,
			numTokenTransfers: 0,
			expectedErr:       false,
			validateResult: func(t *testing.T, result *ReceiptStructure) {
				assert.Len(t, result.CCVReceipts, 1)
				assert.Len(t, result.TokenReceipts, 0)
				assert.Len(t, result.CCVAddresses, 1)

				// Validate CCV receipt
				assert.Equal(t, UnknownAddress([]byte{0xCC, 0x01}), result.CCVReceipts[0].Issuer)
				assert.Equal(t, []byte{0xAA, 0xBB}, []byte(result.CCVReceipts[0].Blob))
				assert.Equal(t, []byte{0xCC, 0x01}, []byte(result.CCVAddresses[0]))

				// Validate executor receipt
				assert.Equal(t, UnknownAddress([]byte{0xEE, 0x01}), result.ExecutorAddress)
				assert.Equal(t, uint64(100000), result.ExecutorReceipt.DestGasLimit)
			},
		},
		{
			name: "single token transfer with executor - no CCVs",
			receipts: []ReceiptWithBlob{
				{
					Issuer:            UnknownAddress([]byte{0xAA, 0x01}),
					DestGasLimit:      75000,
					DestBytesOverhead: 30,
					Blob:              nil,
					ExtraArgs:         []byte{0x33},
					FeeTokenAmount:    big.NewInt(750),
				},
				{
					Issuer:            UnknownAddress([]byte{0xEE, 0x01}),
					DestGasLimit:      100000,
					DestBytesOverhead: 50,
					Blob:              nil,
					ExtraArgs:         []byte{0x44},
					FeeTokenAmount:    big.NewInt(1000),
				},
			},
			numCCVBlobs:       0,
			numTokenTransfers: 1,
			expectedErr:       false,
			validateResult: func(t *testing.T, result *ReceiptStructure) {
				assert.Len(t, result.CCVReceipts, 0)
				assert.Len(t, result.TokenReceipts, 1)
				assert.Len(t, result.CCVAddresses, 0)

				// Token is at index 0 (length-2) when no CCVs
				assert.Equal(t, UnknownAddress([]byte{0xAA, 0x01}), result.TokenReceipts[0].Issuer)
				assert.Equal(t, uint64(75000), result.TokenReceipts[0].DestGasLimit)

				// Executor is at index 1 (length-1)
				assert.Equal(t, UnknownAddress([]byte{0xEE, 0x01}), result.ExecutorAddress)
			},
		},
		{
			name: "multiple CCVs with token and executor",
			receipts: []ReceiptWithBlob{
				// CCV 1
				{
					Issuer:            UnknownAddress([]byte{0xCC, 0x01}),
					DestGasLimit:      50000,
					DestBytesOverhead: 20,
					Blob:              []byte{0xAA, 0xBB},
					ExtraArgs:         []byte{0x11},
					FeeTokenAmount:    big.NewInt(500),
				},
				// CCV 2
				{
					Issuer:            UnknownAddress([]byte{0xCC, 0x02}),
					DestGasLimit:      51000,
					DestBytesOverhead: 21,
					Blob:              []byte{0xCC, 0xDD},
					ExtraArgs:         []byte{0x12},
					FeeTokenAmount:    big.NewInt(510),
				},
				// CCV 3
				{
					Issuer:            UnknownAddress([]byte{0xCC, 0x03}),
					DestGasLimit:      52000,
					DestBytesOverhead: 22,
					Blob:              []byte{0xEE, 0xFF},
					ExtraArgs:         []byte{0x13},
					FeeTokenAmount:    big.NewInt(520),
				},
				// Token (at index length-2, second-to-last)
				{
					Issuer:            UnknownAddress([]byte{0xAA, 0x01}),
					DestGasLimit:      75000,
					DestBytesOverhead: 30,
					Blob:              nil,
					ExtraArgs:         []byte{0x21},
					FeeTokenAmount:    big.NewInt(750),
				},
				// Executor (at index length-1, last)
				{
					Issuer:            UnknownAddress([]byte{0xEE, 0x01}),
					DestGasLimit:      100000,
					DestBytesOverhead: 50,
					Blob:              nil,
					ExtraArgs:         []byte{0x99},
					FeeTokenAmount:    big.NewInt(1000),
				},
			},
			numCCVBlobs:       3,
			numTokenTransfers: 1,
			expectedErr:       false,
			validateResult: func(t *testing.T, result *ReceiptStructure) {
				// Validate counts
				assert.Len(t, result.CCVReceipts, 3)
				assert.Len(t, result.TokenReceipts, 1)
				assert.Len(t, result.CCVAddresses, 3)

				// Validate CCV receipts and addresses
				for i := 0; i < 3; i++ {
					expectedIssuer := UnknownAddress([]byte{0xCC, byte(i + 1)})
					assert.Equal(t, expectedIssuer, result.CCVReceipts[i].Issuer)
					assert.Equal(t, expectedIssuer.Bytes(), []byte(result.CCVAddresses[i]))
					assert.NotNil(t, result.CCVReceipts[i].Blob)
					assert.NotEmpty(t, result.CCVReceipts[i].Blob)
				}

				// Validate token receipt (at index length-2)
				assert.Equal(t, UnknownAddress([]byte{0xAA, 0x01}), result.TokenReceipts[0].Issuer)
				assert.Nil(t, result.TokenReceipts[0].Blob)

				// Validate executor receipt
				assert.Equal(t, UnknownAddress([]byte{0xEE, 0x01}), result.ExecutorAddress)
				assert.Equal(t, uint64(100000), result.ExecutorReceipt.DestGasLimit)
				assert.Nil(t, result.ExecutorReceipt.Blob)
			},
		},
		{
			name: "mismatch - too few receipts",
			receipts: []ReceiptWithBlob{
				{Issuer: UnknownAddress([]byte{0x01})},
				{Issuer: UnknownAddress([]byte{0x02})},
			},
			numCCVBlobs:       2,
			numTokenTransfers: 1,
			expectedErr:       true,
			expectedErrMsg:    "unexpected receipt count: got 2, expected 4 (CCVs=2 + Tokens=1 + Executor=1)",
		},
		{
			name: "mismatch - too many receipts",
			receipts: []ReceiptWithBlob{
				{Issuer: UnknownAddress([]byte{0x01})},
				{Issuer: UnknownAddress([]byte{0x02})},
				{Issuer: UnknownAddress([]byte{0x03})},
				{Issuer: UnknownAddress([]byte{0x04})},
			},
			numCCVBlobs:       1,
			numTokenTransfers: 1,
			expectedErr:       true,
			expectedErrMsg:    "unexpected receipt count: got 4, expected 3 (CCVs=1 + Tokens=1 + Executor=1)",
		},
		{
			name: "edge case - many CCVs",
			receipts: func() []ReceiptWithBlob {
				receipts := make([]ReceiptWithBlob, 11) // 10 CCVs + 1 executor
				for i := 0; i < 10; i++ {
					receipts[i] = ReceiptWithBlob{
						Issuer:       UnknownAddress([]byte{0xCC, byte(i)}),
						Blob:         []byte{byte(i)},
						DestGasLimit: uint64(50000 + i*1000),
					}
				}
				receipts[10] = ReceiptWithBlob{
					Issuer:       UnknownAddress([]byte{0xEE}),
					DestGasLimit: 100000,
				}
				return receipts
			}(),
			numCCVBlobs:       10,
			numTokenTransfers: 0,
			expectedErr:       false,
			validateResult: func(t *testing.T, result *ReceiptStructure) {
				assert.Len(t, result.CCVReceipts, 10)
				assert.Len(t, result.TokenReceipts, 0)
				assert.Len(t, result.CCVAddresses, 10)
				assert.Equal(t, UnknownAddress([]byte{0xEE}), result.ExecutorAddress)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseReceiptStructure(tt.receipts, tt.numCCVBlobs, tt.numTokenTransfers)

			if tt.expectedErr {
				require.Error(t, err)
				if tt.expectedErrMsg != "" {
					assert.Contains(t, err.Error(), tt.expectedErrMsg)
				}
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}
