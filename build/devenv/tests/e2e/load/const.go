package load

import "time"

const (
	SentMessageChannelBufferSize    = 1000
	AvgMsgDataSize                  = 1000 // bytes
	PendingMessageChannelBufferSize = 1000

	// FAFReceiptWorkers is the number of workers that will be used to process receipts from fire-and-forget load gun.
	FAFReceiptWorkers = 10
	// FAFPollInterval is the interval at which the fire-and-forget load gun will poll for receipts.
	FAFPollInterval = 1 * time.Second
	// FAFPollTimeout is the timeout for the fire-and-forget load gun to wait for receipts before giving up.
	FAFPollTimeout = 2 * time.Minute
)
