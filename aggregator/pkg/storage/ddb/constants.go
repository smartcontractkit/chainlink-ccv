package ddb

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
)

const (
	ConditionPreventDuplicateRecord        = "attribute_not_exists(" + FieldPartitionKey + ") AND attribute_not_exists(" + FieldSortKey + ")"
	ConditionPreventDuplicateAccumulator   = "attribute_not_exists(" + FieldSortKey + ")"
	ConditionPreventDuplicateFinalizedFeed = "attribute_not_exists(" + FinalizedFeedFieldCommitteeIDMessageID + ") AND attribute_not_exists(" + FinalizedFeedFieldFinalizedAt + ")"
)

const (
	GSIDayCommitteeIndex = "Day-Committee-Index"
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
