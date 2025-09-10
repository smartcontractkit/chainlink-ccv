package leaderelector

import (
	"math/rand"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

type RandomDelayLeader struct{}

// GetDelay should return a random int64 between 0 and 15 seconds
func (s *RandomDelayLeader) GetDelay(messageID types.Bytes32, destSelector types.ChainSelector, readyTimestamp int64) int64 {
	// Use message ID and timestamp to create a deterministic but pseudo-random seed
	// This ensures different messages get different delays but the same message always gets the same delay
	r := rand.New(rand.NewSource(int64(destSelector) + readyTimestamp))

	return r.Int63n(10)
}
