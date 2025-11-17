package protocol

import "time"

type MessagesV1Request struct {
	SourceChainSelectors []ChainSelector // Excluded from form due to gin parsing
	DestChainSelectors   []ChainSelector // Excluded from form due to gin parsing
	Start                time.Time       `form:"start"`
	End                  time.Time       `form:"end"`
	Limit                uint64          `form:"limit"`
	Offset               uint64          `form:"offset"`
}

type MessagesV1Response struct {
	Messages map[string]Message `json:"messages"`
	Error    string             `json:"error,omitempty"`
	Success  bool               `json:"success"`
}

type MessageIDV1Response struct {
	Error           string    `json:"error,omitempty"`
	Success         bool      `json:"success"`
	VerifierResults []CCVData `json:"verifierResults"`
}
