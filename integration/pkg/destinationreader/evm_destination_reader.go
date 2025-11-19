package destinationreader

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/rmnremotereader"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
)

// Ensure ChainlinkExecutor implements the Executor interface.
var (
	// Ensure EvmDestinationReader implements the DestinationReader interface.
	_                    = executor.DestinationReader(&EvmDestinationReader{})
	curseCacheMaxEntries = 100
	// This 1000 number is arbitrary, it can be adjusted as needed depending on usage pattern.
	VERIFIER_QUORUM_CACHE_MAX_ENTRIES = 1000
)

type verifierQuorumCacheKey struct {
	sourceChainSelector protocol.ChainSelector
	receiverAddress     string
}

type curseCacheKey struct {
	sourceChainSelector protocol.ChainSelector
}

type EvmDestinationReader struct {
	offRampCaller   offramp.OffRampCaller
	rmnRemoteCaller rmn_remote.RMNRemoteCaller
	lggr            logger.Logger
	client          bind.ContractCaller
	chainSelector   protocol.ChainSelector
	ccvCache        *expirable.LRU[verifierQuorumCacheKey, executor.CCVAddressInfo]
	curseCache      *expirable.LRU[protocol.ChainSelector, bool]
}

type Params struct {
	Lggr             logger.Logger
	ChainSelector    protocol.ChainSelector
	ChainClient      client.Client
	OfframpAddress   string
	RmnRemoteAddress string
	CacheExpiry      time.Duration
}

func NewEvmDestinationReader(params Params) *EvmDestinationReader {
	offRampAddr := common.HexToAddress(params.OfframpAddress)
	offRamp, err := offramp.NewOffRampCaller(offRampAddr, params.ChainClient)
	if err != nil {
		params.Lggr.Errorw("Failed to create Off Ramp caller", "error", err, "address", offRampAddr.Hex(), "chainSelector", params.ChainSelector)
	}

	rmnRemoteAddr := common.HexToAddress(params.RmnRemoteAddress)
	rmnRemote, err := rmn_remote.NewRMNRemoteCaller(rmnRemoteAddr, params.ChainClient)
	if err != nil {
		params.Lggr.Errorw("Failed to create RMN Remote caller", "error", err, "address", rmnRemoteAddr.Hex(), "chainSelector", params.ChainSelector)
	}

	// Create cache with max 1000 entries and configurable expiry for verifier quorum info.
	ccvCache := expirable.NewLRU[verifierQuorumCacheKey, executor.CCVAddressInfo](VERIFIER_QUORUM_CACHE_MAX_ENTRIES, nil, params.CacheExpiry)
	curseCache := expirable.NewLRU[protocol.ChainSelector, bool](curseCacheMaxEntries, nil, params.CacheExpiry)

	return &EvmDestinationReader{
		offRampCaller:   *offRamp,
		rmnRemoteCaller: *rmnRemote,
		lggr:            params.Lggr,
		chainSelector:   params.ChainSelector,
		client:          params.ChainClient,
		ccvCache:        ccvCache,
		curseCache:      curseCache,
	}
}

// GetCCVSForMessage implements the DestinationReader interface. It uses the chainlink-evm client to call the get_ccvs function on the receiver contract.
// The ABI is defined here https://github.com/smartcontractkit/chainlink-ccip/blob/0e7fcfd20ab005d75d0eb863790470f91fa5b8d7/chains/evm/contracts/interfaces/IAny2EVMMessageReceiverV2.sol
func (dr *EvmDestinationReader) GetCCVSForMessage(ctx context.Context, message protocol.Message) (executor.CCVAddressInfo, error) {
	_ = ctx
	receiverAddress, sourceSelector := message.Receiver, message.SourceChainSelector
	// Try to get CCV info from cache first
	// TODO: We need to find a way to cache token transfer CCV info as well
	ccvInfo, found := dr.ccvCache.Peek(verifierQuorumCacheKey{sourceChainSelector: sourceSelector, receiverAddress: receiverAddress.String()})
	if found && message.TokenTransferLength == 0 {
		dr.lggr.Debugf("CCV info retrieved from cache for receiver %s on source chain %d",
			receiverAddress.String(), sourceSelector)
		return ccvInfo, nil
	}

	encodedMsg, err := message.Encode()
	if err != nil {
		return executor.CCVAddressInfo{}, fmt.Errorf("failed to encode message: %w", err)
	}
	chainCCVInfo, err := dr.offRampCaller.GetCCVsForMessage(nil, encodedMsg)
	if err != nil {
		return executor.CCVAddressInfo{}, fmt.Errorf("failed to call GetCCVSForMessage: %w", err)
	}

	req, opt, optThreshold := chainCCVInfo.RequiredCCVs, chainCCVInfo.OptionalCCVs, chainCCVInfo.Threshold

	requiredCCVs := make([]protocol.UnknownAddress, 0)
	optionalCCVs := make([]protocol.UnknownAddress, 0)
	for _, addr := range req {
		requiredCCVs = append(requiredCCVs, protocol.UnknownAddress(addr.Bytes()))
	}

	for _, addr := range opt {
		optionalCCVs = append(optionalCCVs, protocol.UnknownAddress(addr.Bytes()))
	}

	ccvInfo = executor.CCVAddressInfo{
		RequiredCCVs:      requiredCCVs,
		OptionalCCVs:      optionalCCVs,
		OptionalThreshold: optThreshold,
	}

	dr.lggr.Infow("Using CCV Info",
		"sourceChain", sourceSelector,
		"receiver", receiverAddress.String(),
		"chain", dr.chainSelector,
		"ccvInfo", ccvInfo,
	)

	// Store in expirable cache for future use
	dr.ccvCache.Add(verifierQuorumCacheKey{sourceChainSelector: sourceSelector, receiverAddress: receiverAddress.String()}, ccvInfo)
	dr.lggr.Debugf("CCV info cached for receiver %s on source chain %d: %+v",
		receiverAddress.String(), sourceSelector, ccvInfo)

	return ccvInfo, nil
}

// GetMessageExecutionState checks the destination chain to verify if a message has been executed.
func (dr *EvmDestinationReader) GetMessageExecutionState(ctx context.Context, message protocol.Message) (executor.MessageExecutionState, error) {
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
		// expect that the error is checked by the caller so it doesn't accidentally assume success
		return 0, fmt.Errorf("failed to call getExecutionState: %w", err)
	}

	return executor.MessageExecutionState(execState), nil
}

// IsCursed checks if the message lane is cursed, or if there is a global curse on the destination.
// We use a 5 minute cache for this check as an optimization for surge message scenarios.
// If we have a stale cache state, message will eventually be retried either by another executor or by this one.
func (dr *EvmDestinationReader) GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error) {
	// We use an abstracted function to reuse code between verifier and executor.
	return rmnremotereader.EVMReadRMNCursedSubjects(ctx, dr.rmnRemoteCaller)
}
