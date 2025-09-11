package leaderelector

import (
	"math/rand"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

type RandomDelayLeader struct{}

// GetDelay should return a random int64 delay in seconds
func (s *RandomDelayLeader) GetReadyTimestamp(messageID types.Bytes32, message types.Message, verifierTimestamp int64) int64 {
	// Use message ID and timestamp to create a deterministic but pseudo-random seed
	// This ensures different messages get different delays but the same message always gets the same delay
	r := rand.New(rand.NewSource(int64(message.DestChainSelector) + verifierTimestamp))

	return r.Int63n(10) + verifierTimestamp
}

type RandSource struct {
	destSelector   types.ChainSelector
	readyTimestamp int64
}

func (rs RandSource) Uint64() uint64 {
	return uint64(rs.destSelector) + uint64(rs.readyTimestamp) //nolint: gosec
}
