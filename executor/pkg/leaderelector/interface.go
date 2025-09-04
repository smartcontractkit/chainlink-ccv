package leaderelector

import (
	"github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
)

type LeaderElector interface {
	GetDelay(messageId ccipocr3.Bytes32, destSelector ccipocr3.ChainSelector, readyTimestamp uint64) uint64
}
