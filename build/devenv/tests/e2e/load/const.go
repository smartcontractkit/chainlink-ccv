package load

import "time"

const (
	SentMessageChannelBufferSize    = 1000
	AvgMsgDataSize                  = 1000 // bytes
	PendingMessageChannelBufferSize = 1000

	FAFReceiptWorkers = 10
	FAFPollInterval   = 1 * time.Second
	FAFPollTimeout    = 2 * time.Minute
)
