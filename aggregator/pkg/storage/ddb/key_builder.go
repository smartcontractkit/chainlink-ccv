package ddb

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"

	ddbconstant "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb/constants"
)

func BuildPartitionKey(messageID []byte, committeeID string) string {
	messageIDHex := hex.EncodeToString(messageID)
	return fmt.Sprintf("%s%s%s", committeeID, ddbconstant.KeySeparator, messageIDHex)
}

func BuildSignatureSortKey(signerAddressHex string, timestamp int64) string {
	return fmt.Sprintf("%s%s%s%s%d", ddbconstant.SignatureRecordPrefix, ddbconstant.KeySeparator, signerAddressHex, ddbconstant.KeySeparator, timestamp)
}

func BuildFinalizedFeedPartitionKey(committeeID string, messageID model.MessageID) string {
	return fmt.Sprintf("%s%s%s", committeeID, ddbconstant.KeySeparator, hex.EncodeToString(messageID))
}

func BuildFinalizedFeedSortKey(finalizedAt int64, verificationCount int) string {
	return fmt.Sprintf("%d%s%d", finalizedAt, ddbconstant.KeySeparator, verificationCount)
}

func BuildGSIPartitionKey(day, committeeID string, version int, shard string) string {
	return fmt.Sprintf("%s%s%s%sv%d%s%s", day, ddbconstant.KeySeparator, committeeID, ddbconstant.KeySeparator, version, ddbconstant.KeySeparator, shard)
}

func BuildGSISortKey(finalizedAt int64, verificationCount int, messageIDHex string) string {
	return fmt.Sprintf("%010d%s%05d%s%s", finalizedAt, ddbconstant.KeySeparator, verificationCount, ddbconstant.KeySeparator, messageIDHex)
}

func ComputeFinalizedAt(report *model.CommitAggregatedReport) int64 {
	if len(report.Verifications) == 0 {
		return time.Now().Unix()
	}

	return report.Timestamp
}

func FormatDay(timestampSeconds int64) string {
	return time.Unix(timestampSeconds, 0).UTC().Format("2006-01-02")
}
