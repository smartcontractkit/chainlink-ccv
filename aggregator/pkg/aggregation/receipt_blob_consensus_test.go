package aggregation

import (
	"sort"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func TestSelectWinningReceiptBlobSet(t *testing.T) {
	tests := []struct {
		name          string
		verifications []*model.CommitVerificationRecord
		expected      []*model.ReceiptBlob
	}{
		{
			name:          "empty verifications",
			verifications: nil,
			expected:      nil,
		},
		{
			name: "single verification",
			verifications: []*model.CommitVerificationRecord{
				createTestVerification(1000, []*pb.ReceiptBlob{
					{Issuer: []byte{1}, Blob: []byte("blob1")},
				}),
			},
			expected: []*model.ReceiptBlob{
				{Issuer: []byte{1}, Blob: []byte("blob1")},
			},
		},
		{
			name: "majority wins - 2 vs 1",
			verifications: []*model.CommitVerificationRecord{
				createTestVerification(1000, []*pb.ReceiptBlob{
					{Issuer: []byte{1}, Blob: []byte("blob1")},
				}),
				createTestVerification(1001, []*pb.ReceiptBlob{
					{Issuer: []byte{1}, Blob: []byte("blob1")},
				}),
				createTestVerification(1002, []*pb.ReceiptBlob{
					{Issuer: []byte{2}, Blob: []byte("blob2")},
				}),
			},
			expected: []*model.ReceiptBlob{
				{Issuer: []byte{1}, Blob: []byte("blob1")},
			},
		},
		{
			name: "tie broken by latest timestamp",
			verifications: []*model.CommitVerificationRecord{
				createTestVerification(1000, []*pb.ReceiptBlob{
					{Issuer: []byte{1}, Blob: []byte("blob1")},
				}),
				createTestVerification(2000, []*pb.ReceiptBlob{
					{Issuer: []byte{2}, Blob: []byte("blob2")},
				}),
			},
			expected: []*model.ReceiptBlob{
				{Issuer: []byte{2}, Blob: []byte("blob2")},
			},
		},
		{
			name: "complex scenario with all fields",
			verifications: []*model.CommitVerificationRecord{
				createTestVerification(1000, []*pb.ReceiptBlob{
					{
						Issuer:            []byte{1},
						DestGasLimit:      100,
						DestBytesOverhead: 10,
						Blob:              []byte("data1"),
						ExtraArgs:         []byte("args1"),
					},
				}),
				createTestVerification(1001, []*pb.ReceiptBlob{
					{
						Issuer:            []byte{1},
						DestGasLimit:      100,
						DestBytesOverhead: 10,
						Blob:              []byte("data1"),
						ExtraArgs:         []byte("args1"),
					},
				}),
				createTestVerification(1002, []*pb.ReceiptBlob{
					{
						Issuer:            []byte{2},
						DestGasLimit:      200,
						DestBytesOverhead: 20,
						Blob:              []byte("data2"),
						ExtraArgs:         []byte("args2"),
					},
				}),
			},
			expected: []*model.ReceiptBlob{
				{
					Issuer:            []byte{1},
					DestGasLimit:      100,
					DestBytesOverhead: 10,
					Blob:              []byte("data1"),
					ExtraArgs:         []byte("args1"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := selectWinningReceiptBlobSet(tt.verifications)
			if err != nil {
				t.Fatalf("selectWinningReceiptBlobSet() error = %v", err)
			}

			if !equalReceiptBlobSlices(result, tt.expected) {
				t.Errorf("selectWinningReceiptBlobSet() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestCreateReceiptBlobSetKey(t *testing.T) {
	tests := []struct {
		name     string
		blobs    []*model.ReceiptBlob
		expected string
	}{
		{
			name:     "empty set",
			blobs:    nil,
			expected: "EMPTY_SET",
		},
		{
			name:     "empty slice",
			blobs:    []*model.ReceiptBlob{},
			expected: "EMPTY_SET",
		},
		{
			name: "single blob with all fields",
			blobs: []*model.ReceiptBlob{
				{
					Issuer:            []byte{1, 2, 3},
					DestGasLimit:      100,
					DestBytesOverhead: 10,
					Blob:              []byte("test"),
					ExtraArgs:         []byte("args"),
				},
			},
			expected: "deterministic_hash", // Will be validated for length
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := createReceiptBlobSetKey(tt.blobs)
			if err != nil {
				t.Fatalf("createReceiptBlobSetKey() error = %v", err)
			}

			if tt.expected == "deterministic_hash" {
				// Validate it's a valid SHA256 hex string
				if len(result) != 64 {
					t.Errorf("createReceiptBlobSetKey() should produce 64-char hex string, got %d chars", len(result))
				}
			} else if result != tt.expected {
				t.Errorf("createReceiptBlobSetKey() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestCreateReceiptBlobSetKey_OrderIndependence(t *testing.T) {
	blob1 := &model.ReceiptBlob{Issuer: []byte{1}, Blob: []byte("blob1")}
	blob2 := &model.ReceiptBlob{Issuer: []byte{2}, Blob: []byte("blob2")}
	blob3 := &model.ReceiptBlob{Issuer: []byte{3}, Blob: []byte("blob3")}

	// Test different orderings produce the same key
	order1 := []*model.ReceiptBlob{blob1, blob2, blob3}
	order2 := []*model.ReceiptBlob{blob3, blob1, blob2}
	order3 := []*model.ReceiptBlob{blob2, blob3, blob1}

	key1, err := createReceiptBlobSetKey(order1)
	if err != nil {
		t.Fatalf("createReceiptBlobSetKey() error = %v", err)
	}
	key2, err := createReceiptBlobSetKey(order2)
	if err != nil {
		t.Fatalf("createReceiptBlobSetKey() error = %v", err)
	}
	key3, err := createReceiptBlobSetKey(order3)
	if err != nil {
		t.Fatalf("createReceiptBlobSetKey() error = %v", err)
	}

	if key1 != key2 || key1 != key3 {
		t.Errorf("Order independence failed: key1=%s, key2=%s, key3=%s", key1, key2, key3)
	}
}

// Helper functions

func createTestVerification(timestamp int64, receiptBlobs []*pb.ReceiptBlob) *model.CommitVerificationRecord {
	modelReceiptBlobs := make([]*model.ReceiptBlob, len(receiptBlobs))
	for i, blob := range receiptBlobs {
		modelReceiptBlobs[i] = &model.ReceiptBlob{
			Issuer:            blob.Issuer,
			Blob:              blob.Blob,
			DestGasLimit:      blob.DestGasLimit,
			DestBytesOverhead: blob.DestBytesOverhead,
			ExtraArgs:         blob.ExtraArgs,
		}
	}

	return &model.CommitVerificationRecord{
		Timestamp:    time.UnixMilli(timestamp).UTC(),
		ReceiptBlobs: modelReceiptBlobs,
		CommitteeID:  "test-committee",
	}
}

func equalReceiptBlobSlices(a, b []*model.ReceiptBlob) bool {
	if len(a) != len(b) {
		return false
	}

	if len(a) == 0 {
		return true
	}

	// Sort both slices for comparison
	aCopy := make([]*model.ReceiptBlob, len(a))
	bCopy := make([]*model.ReceiptBlob, len(b))
	copy(aCopy, a)
	copy(bCopy, b)

	sortReceiptBlobs(aCopy)
	sortReceiptBlobs(bCopy)

	for i := range aCopy {
		if !equalReceiptBlobs(aCopy[i], bCopy[i]) {
			return false
		}
	}

	return true
}

func sortReceiptBlobs(blobs []*model.ReceiptBlob) {
	sort.Slice(blobs, func(i, j int) bool {
		return blobs[i].Less(blobs[j])
	})
}

func equalReceiptBlobs(a, b *model.ReceiptBlob) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	return bytesEqual(a.Issuer, b.Issuer) &&
		a.DestGasLimit == b.DestGasLimit &&
		a.DestBytesOverhead == b.DestBytesOverhead &&
		bytesEqual(a.Blob, b.Blob) &&
		bytesEqual(a.ExtraArgs, b.ExtraArgs)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
