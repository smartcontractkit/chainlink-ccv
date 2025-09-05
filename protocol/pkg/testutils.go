package pkg

import (
	"crypto/rand"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// RandomAddress generates a random address for testing
func RandomAddress() (types.UnknownAddress, error) {
	addr := make([]byte, 20)
	if _, err := rand.Read(addr); err != nil {
		return nil, err
	}
	return types.UnknownAddress(addr), nil
}
