package tracing

// Span attribute keys used across the ccip.
const (
	DestChainSelectorKey          = "dest_chain_selector"
	SourceChainSelectorKey        = "source_chain_selector"
	DestChainNameKey              = "dest_chain_name"
	SourceChainNameKey            = "source_chain_name"
	IngestionTimestampKey         = "ingestion_timestamp"
	ReadyTimestampKey             = "ready_timestamp"
	AttemptKey                    = "attempt"
	DelayKey                      = "delay"
	LatestCCVTimestampKey         = "latest_ccv_timestamp"
	MessageIDKey                  = "message_id"
	VerifierIDKey                 = "verifier_id"
	JobIDKey                      = "job_id"
	BlockNumberKey                = "block_number"
	TxHashKey                     = "tx_hash"
	RetryableKey                  = "retryable"
	LatestBlockNumberKey          = "latest_block_number"
	LatestSafeBlockNumberKey      = "latest_safe_block_number"
	LatestFinalizedBlockNumberKey = "latest_finalized_block_number"
)
