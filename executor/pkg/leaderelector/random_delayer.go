package leaderelector

import (
	"math/rand/v2"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

type RandomDelayLeader struct{}

// GetDelay should return a random int64 between 0 and 15 seconds.
func (s *RandomDelayLeader) GetDelay(messageID types.Bytes32, destSelector types.ChainSelector, readyTimestamp int64) int64 {
	// Use message ID and timestamp to create a deterministic but pseudo-random seed
	// This ensures different messages get different delays but the same message always gets the same delay
	r := rand.New(RandSource{ //nolint:gosec //G115: ignore not used for crypto
		destSelector:   destSelector,
		readyTimestamp: readyTimestamp,
	})

	return r.Int64N(10)
}

type RandSource struct {
	destSelector   types.ChainSelector
	readyTimestamp int64
}

func (rs RandSource) Uint64() uint64 {
	return uint64(rs.destSelector) + uint64(rs.readyTimestamp) //nolint: gosec
}
