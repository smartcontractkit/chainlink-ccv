package cursedetector

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
)

// ReadRMNCursedSubjects queries an RMN Remote contract and returns cursed subjects.
// This is a common helper function that both EVMSourceReader and EVMDestinationReader can use.
//
// Returns cursed subjects as bytes16, which can be:
// - Global curse constant (0x0100000000000000000000000000000001)
// - Chain selector (last 8 bytes) of a cursed remote chain
func ReadRMNCursedSubjects(
	ctx context.Context,
	chainClient client.Client,
	rmnRemoteAddress common.Address,
) ([]protocol.Bytes16, error) {
	// Bind to RMN Remote contract
	rmnRemote, err := rmn_remote.NewRMNRemoteCaller(rmnRemoteAddress, chainClient)
	if err != nil {
		return nil, fmt.Errorf("failed to bind RMN Remote contract at %s: %w",
			rmnRemoteAddress.Hex(), err)
	}

	// Call GetCursedSubjects()
	subjects, err := rmnRemote.GetCursedSubjects(&bind.CallOpts{Context: ctx})
	if err != nil {
		return nil, fmt.Errorf("failed to call GetCursedSubjects: %w", err)
	}

	// Convert [][16]byte to []protocol.Bytes16
	result := make([]protocol.Bytes16, len(subjects))
	for i, subject := range subjects {
		copy(result[i][:], subject[:])
	}

	return result, nil
}
