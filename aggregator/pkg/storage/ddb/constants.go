package ddb

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
	AccumulatorFieldMessageID             = "MessageID"
	AccumulatorFieldSourceVerifierAddress = "SourceVerifierAddress"
	AccumulatorFieldMessage               = "Message"
	AccumulatorFieldBlobData              = "BlobData"
	AccumulatorFieldTimestamp             = "Timestamp"
	AccumulatorFieldReceiptBlobs          = "ReceiptBlobs"
	AccumulatorFieldQuorumStatus          = "QuorumStatus"
	AccumulatorFieldPendingAggregation    = "PendingAggregation"
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
)

const (
	SignatureRecordPrefix   = "SIGNATURE"
	AccumulatorRecordPrefix = "ACCUMULATOR"
)

const (
	KeySeparator       = "#"
	AccumulatorSortKey = AccumulatorRecordPrefix
)

const (
	AccumulatorQuorumStatusPending = "PENDING"
	PendingAggregationPrefix       = "PENDING"
	PendingShardIndex              = 0 // Start with single shard, can be increased later
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
	QueryOrphanedRecordsByPending       = AccumulatorFieldPendingAggregation + " = :pending_key"
)

const (
	ConditionPreventDuplicateRecord        = "attribute_not_exists(" + FieldPartitionKey + ") AND attribute_not_exists(" + FieldSortKey + ")"
	ConditionPreventDuplicateAccumulator   = "attribute_not_exists(" + FieldSortKey + ")"
	ConditionPreventDuplicateFinalizedFeed = "attribute_not_exists(" + FinalizedFeedFieldCommitteeIDMessageID + ") AND attribute_not_exists(" + FinalizedFeedFieldFinalizedAt + ")"
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
