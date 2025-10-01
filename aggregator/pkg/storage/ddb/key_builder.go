package ddb

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

func BuildPartitionKey(messageID []byte, committeeID string) string {
	messageIDHex := hex.EncodeToString(messageID)
	return fmt.Sprintf("%s%s%s", committeeID, KeySeparator, messageIDHex)
}

func BuildSignatureSortKey(signerAddressHex string, timestamp int64) string {
	return fmt.Sprintf("%s%s%s%s%d", SignatureRecordPrefix, KeySeparator, signerAddressHex, KeySeparator, timestamp)
}

func BuildFinalizedFeedPartitionKey(committeeID string, messageID model.MessageID) string {
	return fmt.Sprintf("%s%s%s", committeeID, KeySeparator, hex.EncodeToString(messageID))
}

func BuildFinalizedFeedSortKey(finalizedAt int64) string {
	return strconv.FormatInt(finalizedAt, 10)
}

func BuildGSIPartitionKey(day, committeeID string, version int, shard string) string {
	return fmt.Sprintf("%s%s%s%sv%d%s%s", day, KeySeparator, committeeID, KeySeparator, version, KeySeparator, shard)
}

func BuildGSISortKey(finalizedAt int64, verificationCount int, messageIDHex string) string {
	return fmt.Sprintf("%013d%s%05d%s%s", finalizedAt, KeySeparator, verificationCount, KeySeparator, messageIDHex)
}

func ComputeFinalizedAt(report *model.CommitAggregatedReport) int64 {
	if len(report.Verifications) == 0 {
		return time.Now().UnixMilli()
	}

	return report.Timestamp / 1000
}

func FormatDay(timestampMs int64) string {
	return time.Unix(timestampMs/1000, 0).UTC().Format("2006-01-02")
}
