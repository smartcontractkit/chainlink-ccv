package common

import "errors"

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
