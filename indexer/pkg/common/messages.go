package common

import (
	"encoding/json"
)

// SkippedMessage describes a message that was skipped by FilterEncodableMessages.
type SkippedMessage struct {
	Index  int
	Reason string
}

// FilterEncodableMessages returns messages that can be encoded for storage (MessageID and JSON marshal succeed).
// Messages that fail either check are returned in skipped with index and reason so callers can log them.
func FilterEncodableMessages(messages []MessageWithMetadata) (encodable []MessageWithMetadata, skipped []SkippedMessage) {
	encodable = make([]MessageWithMetadata, 0, len(messages))
	for i, msg := range messages {
		if _, err := json.Marshal(msg.Message); err != nil {
			skipped = append(skipped, SkippedMessage{Index: i, Reason: err.Error()})
			continue
		}
		if _, err := msg.Message.MessageID(); err != nil {
			skipped = append(skipped, SkippedMessage{Index: i, Reason: err.Error()})
			continue
		}
		encodable = append(encodable, msg)
	}
	return encodable, skipped
}
