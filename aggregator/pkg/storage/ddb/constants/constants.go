package ddb_contant

import (
	"fmt"
)

const (
	FinalizedFeedVersion = 1
	FinalizedFeedShard   = "s00"
)

const (
	FieldPartitionKey = "CommitteeID_MessageID"
	FieldSortKey      = "RecordType_Identifier_Timestamp"
	FieldCreatedAt    = "CreatedAt"
)

const (
	SignatureFieldSignerAddress = "SignerAddress"
	SignatureFieldParticipantID = "ParticipantID"
	SignatureFieldSignatureR    = "SignatureR"
	SignatureFieldSignatureS    = "SignatureS"
)

const (
	VerificationMessageDataFieldMessageID             = "MessageID"
	VerificationMessageDataFieldSourceVerifierAddress = "SourceVerifierAddress"
	VerificationMessageDataFieldMessage               = "Message"
	VerificationMessageDataFieldBlobData              = "BlobData"
	VerificationMessageDataFieldTimestamp             = "Timestamp"
	VerificationMessageDataFieldReceiptBlobs          = "ReceiptBlobs"
	VerificationMessageDataFieldQuorumStatus          = "QuorumStatus"
	VerificationMessageDataFieldPendingAggregation    = "PendingAggregation"
)

const (
	FinalizedFeedFieldGSIPK = "DayCommitteePartition"
	FinalizedFeedFieldGSISK = "TimeSeqMessage"
)

const (
	FinalizedFeedFieldMessageID            = "MessageID"
	FinalizedFeedFieldCommitteeID          = "CommitteeID"
	FinalizedFeedFieldCommitteeIDMessageID = "CommitteeID_MessageID"
	FinalizedFeedFieldFinalizedAt          = "FinalizedAt"
	FinalizedFeedFieldAggregatedReportData = "AggregatedReportData"
	FinalizedFeedFieldTimestamp            = "Timestamp"
	FinalizedFeedFieldWrittenAt            = "WrittenAt"
)

const (
	SignatureRecordPrefix               = "SIGNATURE"
	VerificationMessageDataRecordPrefix = "VERIFICATION_MESSAGE_DATA"
)

const (
	KeySeparator                   = "#"
	VerificationMessageDataSortKey = VerificationMessageDataRecordPrefix
)

const (
	VerificationMessageDataQuorumStatusPending = "PENDING"
	PendingAggregationPrefix                   = "PENDING"
	PendingShardIndex                          = 0 // Start with single shard, can be increased later
)

const (
	QueryAllRecordsInPartition    = FieldPartitionKey + " = :pk"
	QueryRecordsByTypePrefix      = FieldPartitionKey + " = :pk AND begins_with(" + FieldSortKey + ", :sk_prefix)"
	QuerySignatureRecordsBySigner = FieldPartitionKey + " = :pk AND begins_with(" + FieldSortKey + ", :sk_prefix)"
)

const (
	QueryReportsInTimeRange             = FinalizedFeedFieldCommitteeIDMessageID + " = :pk AND " + FinalizedFeedFieldFinalizedAt + " BETWEEN :startKey AND :endKey"
	QueryLatestReportByCommitteeMessage = FinalizedFeedFieldCommitteeIDMessageID + " = :pk"
	QueryReportsInDayCommitteeRange     = FinalizedFeedFieldGSIPK + " = :gsiPK AND " + FinalizedFeedFieldGSISK + " BETWEEN :startKey AND :endKey"
	QueryOrphanedRecordsByPending       = VerificationMessageDataFieldPendingAggregation + " = :pending_key"
)

const (
	ConditionPreventDuplicateRecord                  = "attribute_not_exists(" + FieldPartitionKey + ") AND attribute_not_exists(" + FieldSortKey + ")"
	ConditionPreventDuplicateVerificationMessageData = "attribute_not_exists(" + FieldSortKey + ")"
	ConditionPreventDuplicateFinalizedFeed           = "attribute_not_exists(" + FinalizedFeedFieldCommitteeIDMessageID + ") AND attribute_not_exists(" + FinalizedFeedFieldFinalizedAt + ")"
)

const (
	GSIDayCommitteeIndex       = "Day-Committee-Index"
	GSIPendingAggregationIndex = "PendingAggregation-Index"
)

// Checkpoint Storage Constants.
const (
	CheckpointFieldClientID             = "ClientID"
	CheckpointFieldChainSelector        = "ChainSelector"
	CheckpointFieldFinalizedBlockHeight = "FinalizedBlockHeight"
	CheckpointFieldLastUpdated          = "LastUpdated"
)

const (
	QueryCheckpointsByClient = CheckpointFieldClientID + " = :client_id"
	QueryAllCheckpoints      = "scan"
)

const (
	ConditionPreventDuplicateCheckpoint = "attribute_not_exists(" + CheckpointFieldClientID + ") AND attribute_not_exists(" + CheckpointFieldChainSelector + ")"
)

// Orphan Recovery Helper Functions

// GetPendingAggregationKey generates the pending aggregation key for a committee and shard.
// Format: "PENDING_<committee>_<shard>".
func GetPendingAggregationKey(committeeID string, shard int) string {
	return fmt.Sprintf("%s_%s_%d", PendingAggregationPrefix, committeeID, shard)
}

// GetPendingAggregationKeyForRecord generates the pending aggregation key for a specific record.
// Currently uses shard 0, but can be enhanced to distribute load later.
func GetPendingAggregationKeyForRecord(committeeID string) string {
	return GetPendingAggregationKey(committeeID, PendingShardIndex)
}

// GenerateShardIDs generates a list of shard identifiers (s00, s01, s02, etc.) based on the shard count.
func GenerateShardIDs(shardCount int) []string {
	if shardCount <= 1 {
		return []string{FinalizedFeedShard} // Backward compatibility with single shard "s00"
	}

	shards := make([]string, shardCount)
	for i := 0; i < shardCount; i++ {
		shards[i] = fmt.Sprintf("s%02d", i)
	}
	return shards
}

// CalculateShardFromMessageID calculates which shard a message should be assigned to based on its messageID.
// Uses a deterministic algorithm based on the first 4 bytes of the messageID for consistent shard assignment.
func CalculateShardFromMessageID(messageID []byte, shardCount int) string {
	if shardCount <= 1 {
		return FinalizedFeedShard // Backward compatibility with single shard "s00"
	}

	if shardCount < 0 {
		return FinalizedFeedShard // Safety check for negative values
	}

	if len(messageID) == 0 {
		return "s00" // Fallback for empty messageID
	}

	// Use first 4 bytes of messageID for deterministic hash
	var hash uint32
	for i := 0; i < 4 && i < len(messageID); i++ {
		hash = hash*256 + uint32(messageID[i])
	}

	shardIndex := hash % uint32(shardCount) //nolint:gosec // shardCount validated as positive
	return fmt.Sprintf("s%02d", shardIndex)
}

func CreateShardIDs(shardCount int) []string {
	if shardCount <= 1 {
		return []string{FinalizedFeedShard} // Backward compatibility with single shard "s00"
	}

	shards := make([]string, shardCount)
	for i := 0; i < shardCount; i++ {
		shards[i] = fmt.Sprintf("s%02d", i)
	}
	return shards
}
