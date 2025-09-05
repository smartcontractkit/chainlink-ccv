package leaderelector

import (
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

type LeaderElector interface {
	// GetDelay to check again
	GetDelay(messageID types.Bytes32, destSelector types.ChainSelector, readyTimestamp int64) int64
}
