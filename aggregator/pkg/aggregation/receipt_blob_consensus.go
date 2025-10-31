package aggregation

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// selectWinningReceiptBlobSet determines the winning receipt blob set from verification records.
// It uses majority consensus with latest timestamp tie-breaking.
func selectWinningReceiptBlobSet(verifications []*model.CommitVerificationRecord) ([]*model.ReceiptBlob, error) {
	if len(verifications) == 0 {
		return nil, nil
	}

	// Group verifications by receipt blob set (order-independent)
	setCounts := make(map[string]int)
	setMap := make(map[string][]*model.ReceiptBlob)
	setTimestamps := make(map[string]int64) // For tie-breaking

	for _, verification := range verifications {
		domainBlobs := model.ReceiptBlobsFromProto(verification.ReceiptBlobs)
		setKey, err := createReceiptBlobSetKey(domainBlobs)
		if err != nil {
			return nil, err
		}
		setCounts[setKey]++
		if _, exists := setMap[setKey]; !exists {
			setMap[setKey] = domainBlobs
			setTimestamps[setKey] = verification.GetTimestamp()
		} else {
			// Update to latest timestamp for tie-breaking
			if verification.GetTimestamp() > setTimestamps[setKey] {
				setTimestamps[setKey] = verification.GetTimestamp()
			}
		}
	}

	// Find winning set (most frequent, latest timestamp breaks ties)
	var winningKey string
	maxCount := 0
	latestTimestamp := int64(0)

	for key, count := range setCounts {
		if count > maxCount || (count == maxCount && setTimestamps[key] > latestTimestamp) {
			maxCount = count
			latestTimestamp = setTimestamps[key]
			winningKey = key
		}
	}

	if winningKey == "" {
		return nil, nil
	}

	return setMap[winningKey], nil
}

// createReceiptBlobSetKey creates a deterministic, order-independent key for a set of receipt blobs.
func createReceiptBlobSetKey(blobs []*model.ReceiptBlob) (string, error) {
	if len(blobs) == 0 {
		return "EMPTY_SET", nil
	}

	// Create a copy to avoid modifying the original slice
	sortedBlobs := make([]*model.ReceiptBlob, len(blobs))
	copy(sortedBlobs, blobs)

	// Sort blobs deterministically using the Less method
	sort.Slice(sortedBlobs, func(i, j int) bool {
		return sortedBlobs[i].Less(sortedBlobs[j])
	})

	// Create hash of the entire sorted set
	hasher := sha256.New()
	for _, blob := range sortedBlobs {
		hasher.Write(blob.Issuer)
		if err := binary.Write(hasher, binary.BigEndian, blob.DestGasLimit); err != nil {
			return "", err
		}
		if err := binary.Write(hasher, binary.BigEndian, blob.DestBytesOverhead); err != nil {
			return "", err
		}
		hasher.Write(blob.Blob)
		hasher.Write(blob.ExtraArgs)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
