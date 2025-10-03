package v1

import "github.com/smartcontractkit/chainlink-ccv/protocol"

type MessageIDV1Response struct {
	MessageID     string             `json:"messageID"`
	Verifications []protocol.CCVData `json:"verifications"`
}
