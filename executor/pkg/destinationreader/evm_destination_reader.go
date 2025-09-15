package destinationreader

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"

	"github.com/smartcontractkit/chainlink-ccv/common/pkg"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	mockReceiver "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/mock_receiver_v2"
	commontypes "github.com/smartcontractkit/chainlink-ccv/common/pkg/types"
	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

type EvmDestinationReader struct {
	ctx           context.Context
	lggr          logger.Logger
	chainSelector uint64
	client        bind.ContractCaller
}

func NewEvmDestinationReaderFromChainInfo(ctx context.Context, lggr logger.Logger, chainSelector uint64, chainInfo *commontypes.BlockchainInfo) *EvmDestinationReader {
	chainClient := pkg.CreateMultiNodeClientFromInfo(ctx, chainInfo, lggr)

	return &EvmDestinationReader{
		lggr:          lggr,
		chainSelector: chainSelector,
		client:        chainClient,
	}
}

// GetCCVSForMessage implements the DestinationReader interface. It uses the chainlink-evm client to call the get_ccvs function on the receiver contract.
// The ABI is defined here https://github.com/smartcontractkit/chainlink-ccip/blob/0e7fcfd20ab005d75d0eb863790470f91fa5b8d7/chains/evm/contracts/interfaces/IAny2EVMMessageReceiverV2.sol
func (dr *EvmDestinationReader) GetCCVSForMessage(ctx context.Context, sourceSelector protocol.ChainSelector, receiverAddress protocol.UnknownAddress) (types.CcvAddressInfo, error) {
	receiverContract, err := mockReceiver.NewMockReceiverV2Caller(common.HexToAddress(receiverAddress.String()), dr.client)
	if err != nil {
		return types.CcvAddressInfo{}, fmt.Errorf("failed to create receiver contract instance: %w", err)
	}

	req, opt, optThreshold, err := receiverContract.GetCCVs(nil, uint64(sourceSelector))
	if err != nil {
		return types.CcvAddressInfo{}, fmt.Errorf("failed to call getCCVs: %w", err)
	}

	// Convert common.Address slices to protocol.UnknownAddress slices
	requiredCCVs := make([]protocol.UnknownAddress, len(req))
	for i, addr := range req {
		requiredCCVs[i] = protocol.UnknownAddress(addr.Hex())
	}

	optionalCCVs := make([]protocol.UnknownAddress, len(opt))
	for i, addr := range opt {
		optionalCCVs[i] = protocol.UnknownAddress(addr.Hex())
	}

	return types.CcvAddressInfo{
		RequiredCcvs:      requiredCCVs,
		OptionalCcvs:      optionalCCVs,
		OptionalThreshold: optThreshold,
	}, nil
}

// IsMessageExecuted checks the destination chain to verify if a message has been executed
// TODO: Implement this
func (dr *EvmDestinationReader) IsMessageExecuted(ctx context.Context, sourceSelector protocol.ChainSelector, nonce protocol.Nonce) (bool, error) {
	return false, nil
}
