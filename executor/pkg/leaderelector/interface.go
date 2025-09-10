package leaderelector

import (
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

type LeaderElector interface {
	// GetReadyTimestamp to determine when a message is ready to be executed by this executor
	GetReadyTimestamp(messageID types.Bytes32, message types.Message, verifierTimestamp int64) int64
}
