package leaderelector

import (
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type LeaderElector interface {
	// GetReadyTimestamp to determine when a message is ready to be executed by this executor
	GetReadyTimestamp(messageID protocol.Bytes32, message protocol.Message, verifierTimestamp int64) int64
}
