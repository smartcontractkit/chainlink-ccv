package destinationreader

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/common/pkg"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	ccvagg "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
	mockreceiver "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/mock_receiver_v2"
	commontypes "github.com/smartcontractkit/chainlink-ccv/common/pkg/types"
	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

const (
	MESSAGE_UNTOUCHED = iota
	MESSAGE_IN_PROGRESS
	MESSAGE_SUCCESS
	MESSAGE_FAILURE
)

type EvmDestinationReader struct {
	aggregatorCaller ccvagg.CCVAggregatorCaller
	lggr             logger.Logger
	client           bind.ContractCaller
	chainSelector    uint64
}

func NewEvmDestinationReaderFromChainInfo(ctx context.Context, lggr logger.Logger, chainSelector uint64, chainInfo *commontypes.BlockchainInfo) *EvmDestinationReader {
	chainClient := pkg.CreateMultiNodeClientFromInfo(ctx, chainInfo, lggr)

	ccvAddr := common.HexToAddress(chainInfo.OfframpRouter)
	ccvAgg, err := ccvagg.NewCCVAggregatorCaller(ccvAddr, chainClient)
	if err != nil {
		lggr.Errorw("Failed to create CCV Aggregator caller", "error", err, "address", ccvAddr.Hex(), "chainSelector", chainSelector)
	}
	return &EvmDestinationReader{
		aggregatorCaller: *ccvAgg,
		lggr:             lggr,
		chainSelector:    chainSelector,
		client:           chainClient,
	}
}

// GetCCVSForMessage implements the DestinationReader interface. It uses the chainlink-evm client to call the get_ccvs function on the receiver contract.
// The ABI is defined here https://github.com/smartcontractkit/chainlink-ccip/blob/0e7fcfd20ab005d75d0eb863790470f91fa5b8d7/chains/evm/contracts/interfaces/IAny2EVMMessageReceiverV2.sol
func (dr *EvmDestinationReader) GetCCVSForMessage(ctx context.Context, sourceSelector protocol.ChainSelector, receiverAddress protocol.UnknownAddress) (types.CcvAddressInfo, error) {
	_ = ctx
	receiverContract, err := mockreceiver.NewMockReceiverV2Caller(common.HexToAddress(receiverAddress.String()), dr.client)
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
func (dr *EvmDestinationReader) IsMessageExecuted(ctx context.Context, message protocol.Message) (bool, error) {
	_ = ctx

	rcv := common.HexToAddress(string(message.Receiver))
	execState, err := dr.aggregatorCaller.GetExecutionState(
		&bind.CallOpts{
			Context: ctx,
			// TODO: Add FTF to this check
			Pending: false,
		},
		uint64(message.SourceChainSelector),
		uint64(message.Nonce),
		message.Sender,
		rcv)
	if err != nil {
		return false, fmt.Errorf("failed to call getExecutionState: %w", err)
	}

	if execState == MESSAGE_UNTOUCHED || execState == MESSAGE_SUCCESS {
		return true, nil
	}

	return false, nil
}
