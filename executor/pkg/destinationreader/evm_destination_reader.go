package destinationreader

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	evmclient "github.com/smartcontractkit/chainlink-evm/pkg/client"
)

type EvmDestinationReader struct {
	lggr          logger.Logger
	chainSelector uint64
	client        bind.ContractCaller
}

func NewEvmDestinationReaderFromChain(lggr logger.Logger, chainSelector uint64, chainClient evmclient.Client) *EvmDestinationReader {
	return &EvmDestinationReader{
		lggr:          lggr,
		chainSelector: chainSelector,
		client:        chainClient,
	}
}

func NewEvmDestinationReaderFromRPC(lggr logger.Logger, chainSelector protocol.ChainSelector, rpc string) (*EvmDestinationReader, error) {
	// Create an Ethereum client for reading from the blockchain
	client, err := ethclient.Dial(rpc)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum client at %s: %w", rpc, err)
	}

	// ethclient.Client implements bind.ContractCaller interface for reading contract state
	return &EvmDestinationReader{
		lggr:          lggr,
		chainSelector: uint64(chainSelector),
		client:        client,
	}, nil
}

// GetCCVSForMessage implements the DestinationReader interface. It uses the chainlink-evm client to call the get_ccvs function on the receiver contract.
// The ABI is defined here https://github.com/smartcontractkit/chainlink-ccip/blob/0e7fcfd20ab005d75d0eb863790470f91fa5b8d7/chains/evm/contracts/interfaces/IAny2EVMMessageReceiverV2.sol
func (dr *EvmDestinationReader) GetCCVSForMessage(ctx context.Context, sourceSelector protocol.ChainSelector, receiverAddress protocol.UnknownAddress) (types.CcvAddressInfo, error) {
	offRamp, _ := protocol.NewUnknownAddressFromHex("0x959922bE3CAee4b8Cd9a407cc3ac1C251C2007B1")
	return types.CcvAddressInfo{
		RequiredCcvs:      []protocol.UnknownAddress{offRamp},
		OptionalCcvs:      []protocol.UnknownAddress{},
		OptionalThreshold: 0,
	}, nil

	//receiverContract, err := rcv.NewEtherSenderReceiverCaller(common.HexToAddress(receiverAddress.String()), dr.client)
	//if err != nil {
	//	return types.CcvAddressInfo{}, fmt.Errorf("failed to create receiver contract instance: %w", err)
	//}
	//
	//result, err := receiverContract.GetCCVs(nil, uint64(sourceSelector))
	//if err != nil {
	//	return types.CcvAddressInfo{}, fmt.Errorf("failed to call getCCVs: %w", err)
	//}
	//
	//// Convert common.Address slices to protocol.UnknownAddress slices
	//requiredCCVs := make([]protocol.UnknownAddress, len(result.RequiredCCVs))
	//for i, addr := range result.RequiredCCVs {
	//	requiredCCVs[i] = protocol.UnknownAddress(addr.Hex())
	//}
	//
	//optionalCCVs := make([]protocol.UnknownAddress, len(result.OptionalCCVs))
	//for i, addr := range result.OptionalCCVs {
	//	optionalCCVs[i] = protocol.UnknownAddress(addr.Hex())
	//}
	//
	//return types.CcvAddressInfo{
	//	RequiredCcvs:      requiredCCVs,
	//	OptionalCcvs:      optionalCCVs,
	//	OptionalThreshold: result.OptionalThreshold,
	//}, nil
}

// IsMessageExecuted checks the destination chain to verify if a message has been executed
// TODO: Implement this
func (dr *EvmDestinationReader) IsMessageExecuted(ctx context.Context, sourceSelector protocol.ChainSelector, sequenceNumber protocol.SeqNum) (bool, error) {
	return false, nil
}
