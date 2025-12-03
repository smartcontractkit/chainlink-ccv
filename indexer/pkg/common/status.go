package common

import (
	"encoding/json"
	"errors"
)

// MessageStatus is used internally to determine if we should continue to attempt indexing verifications for a given message.
// Consists of 3 potentional states
//
// PROCESSING - Message is currently being indexed for verifications.
// SUCCESS    - Indexer has successfully retrieved all verifications for the message.
// TIMEOUT    - TTL has expired and we no longer attempt to index verifications for this message.
type MessageStatus int

const (
	MessageProcessing MessageStatus = iota
	MessageSuccessful
	MessageTimeout
)

const (
	MessageProcessingString = "PROCESSING"
	MessageSuccessfulString = "SUCCESS"
	MessageTimeoutString    = "TIMEOUT"
	MessageUnknownString    = "UNKNOWN"
)

func (m MessageStatus) String() string {
	switch m {
	case MessageProcessing:
		return MessageProcessingString
	case MessageSuccessful:
		return MessageSuccessfulString
	case MessageTimeout:
		return MessageTimeoutString
	default:
		return MessageUnknownString
	}
}

func (m MessageStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.String())
}

func NewMessageStatusFromString(status string) (MessageStatus, error) {
	switch status {
	case MessageProcessingString:
		return MessageProcessing, nil
	case MessageSuccessfulString:
		return MessageSuccessful, nil
	case MessageTimeoutString:
		return MessageTimeout, nil
	default:
		return 0, errors.New("unknown message status")
	}
}
