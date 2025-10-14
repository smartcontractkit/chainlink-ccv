package destinationreader

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"

	offramp "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/off_ramp"
)

const (
	MESSAGE_UNTOUCHED = iota
	MESSAGE_IN_PROGRESS
	MESSAGE_SUCCESS
	MESSAGE_FAILURE
)

// Ensure ChainlinkExecutor implements the Executor interface.
var _ executor.DestinationReader = &EvmDestinationReader{}

type cacheKey struct {
	sourceChainSelector protocol.ChainSelector
	receiverAddress     string
}
type EvmDestinationReader struct {
	offRampCaller offramp.OffRampCaller
	lggr          logger.Logger
	client        bind.ContractCaller
	chainSelector uint64
	ccvCache      *expirable.LRU[cacheKey, executor.CcvAddressInfo]
}

func NewEvmDestinationReader(lggr logger.Logger, chainSelector uint64, chainClient client.Client, offrampAddress string, cacheExpiry time.Duration) *EvmDestinationReader {
	ccvAddr := common.HexToAddress(offrampAddress)
	ccvAgg, err := offramp.NewOffRampCaller(ccvAddr, chainClient)
	if err != nil {
		lggr.Errorw("Failed to create Off Ramp caller", "error", err, "address", ccvAddr.Hex(), "chainSelector", chainSelector)
	}
	// Create cache with max 1000 entries and configurable expiry
	ccvCache := expirable.NewLRU[cacheKey, executor.CcvAddressInfo](1000, nil, cacheExpiry)

	return &EvmDestinationReader{
		offRampCaller: *ccvAgg,
		lggr:          lggr,
		chainSelector: chainSelector,
		client:        chainClient,
		ccvCache:      ccvCache,
	}
}

// GetCCVSForMessage implements the DestinationReader interface. It uses the chainlink-evm client to call the get_ccvs function on the receiver contract.
// The ABI is defined here https://github.com/smartcontractkit/chainlink-ccip/blob/0e7fcfd20ab005d75d0eb863790470f91fa5b8d7/chains/evm/contracts/interfaces/IAny2EVMMessageReceiverV2.sol
func (dr *EvmDestinationReader) GetCCVSForMessage(ctx context.Context, message protocol.Message) (executor.CcvAddressInfo, error) {
	_ = ctx
	receiverAddress, sourceSelector := message.Receiver, message.SourceChainSelector
	// Try to get CCV info from cache first
	// TODO: Do we need custom cache eviction logic beyond ttl?
	ccvInfo, found := dr.ccvCache.Get(cacheKey{sourceChainSelector: sourceSelector, receiverAddress: string(receiverAddress)})
	if found {
		dr.lggr.Debugf("CCV info retrieved from cache for receiver %s on source chain %d",
			string(receiverAddress), sourceSelector)
		return ccvInfo, nil
	}

	encodedMsg, err := message.Encode()
	if err != nil {
		return executor.CcvAddressInfo{}, fmt.Errorf("failed to encode message: %w", err)
	}
	chainCCVInfo, err := dr.offRampCaller.GetCCVsForMessage(nil, encodedMsg)
	if err != nil {
		return executor.CcvAddressInfo{}, fmt.Errorf("failed to call GetCCVSForMessage: %w", err)
	}

	req, opt, optThreshold := chainCCVInfo.RequiredCCVs, chainCCVInfo.OptionalCCVs, chainCCVInfo.Threshold

	requiredCCVs := make([]protocol.UnknownAddress, 0)
	optionalCCVs := make([]protocol.UnknownAddress, 0)
	for _, addr := range req {
		requiredCCVs = append(requiredCCVs, protocol.UnknownAddress(addr.Hex()))
	}

	for _, addr := range opt {
		optionalCCVs = append(optionalCCVs, protocol.UnknownAddress(addr.Hex()))
	}

	ccvInfo = executor.CcvAddressInfo{
		RequiredCcvs:      requiredCCVs,
		OptionalCcvs:      optionalCCVs,
		OptionalThreshold: optThreshold,
	}

	dr.lggr.Infow("Using CCV Info", "sourceChain", sourceSelector, "receiver", string(receiverAddress), "chain", dr.chainSelector)

	// Store in expirable cache for future use
	dr.ccvCache.Add(cacheKey{sourceChainSelector: sourceSelector, receiverAddress: string(receiverAddress)}, ccvInfo)
	dr.lggr.Debugf("CCV info cached for receiver %s on source chain %d: %+v",
		string(receiverAddress), sourceSelector, ccvInfo)

	return ccvInfo, nil
}

// IsMessageExecuted checks the destination chain to verify if a message has been executed.
func (dr *EvmDestinationReader) IsMessageExecuted(ctx context.Context, message protocol.Message) (bool, error) {
	_ = ctx

	rcv := common.BytesToAddress(message.Receiver)
	execState, err := dr.offRampCaller.GetExecutionState(
		&bind.CallOpts{
			Context: ctx,
			// TODO: Add FTF to this check
		},
		uint64(message.SourceChainSelector),
		uint64(message.Nonce),
		message.Sender,
		rcv)
	if err != nil {
		return false, fmt.Errorf("failed to call getExecutionState: %w", err)
	}

	if execState == MESSAGE_FAILURE || execState == MESSAGE_IN_PROGRESS || execState == MESSAGE_SUCCESS {
		return true, nil
	}
	if execState == MESSAGE_UNTOUCHED {
		return false, nil
	}

	return true, fmt.Errorf("unknown execution state: %d", execState)
}
