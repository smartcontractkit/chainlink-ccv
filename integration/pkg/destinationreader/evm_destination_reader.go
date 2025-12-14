package destinationreader

import (
	"context"
	"errors"
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

var (
	// Ensure EvmDestinationReader implements the DestinationReader interface.
	_ = executor.DestinationReader(&EvmDestinationReader{})

	// This 1000 number is arbitrary, it can be adjusted as needed depending on usage pattern.
	VerifierQuorumCacheMaxEntries = 1000
)

type verifierQuorumCacheKey struct {
	sourceChainSelector  protocol.ChainSelector
	receiverAddress      string
	tokenTransferAddress common.Address
}

type EvmDestinationReader struct {
	offRampCaller          offramp.OffRampCaller
	rmnRemoteCaller        rmn_remote.RMNRemoteCaller
	lggr                   logger.Logger
	client                 bind.ContractCaller
	chainSelector          protocol.ChainSelector
	ccvCache               *expirable.LRU[verifierQuorumCacheKey, executor.CCVAddressInfo]
	executionAttemptPoller *evmExecutionAttemptPoller
}

type Params struct {
	Lggr             logger.Logger
	ChainSelector    protocol.ChainSelector
	ChainClient      client.Client
	OfframpAddress   string
	RmnRemoteAddress string
	CacheExpiry      time.Duration
}

func NewEvmDestinationReader(params Params) (*EvmDestinationReader, error) {
	var errs []error
	appendIfNil := func(field any, fieldName string) {
		if field == nil {
			errs = append(errs, fmt.Errorf("%s is not set", fieldName))
		}
	}

	appendIfNil(params.ChainSelector, "chainSelector")
	appendIfNil(params.OfframpAddress, "offrampAddress")
	appendIfNil(params.RmnRemoteAddress, "rmnRemoteAddress")
	appendIfNil(params.CacheExpiry, "cacheExpiry")
	appendIfNil(params.ChainClient, "chainClient")
	appendIfNil(params.Lggr, "logger")

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	offRampAddr := common.HexToAddress(params.OfframpAddress)
	offRamp, err := offramp.NewOffRampCaller(offRampAddr, params.ChainClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create offramp caller for chain %d: %w", params.ChainSelector, err)
	}

	rmnRemoteAddr := common.HexToAddress(params.RmnRemoteAddress)
	rmnRemote, err := rmn_remote.NewRMNRemoteCaller(rmnRemoteAddr, params.ChainClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create rmn remote caller for chain %d: %w", params.ChainSelector, err)
	}

	// Create cache with max 1000 entries and configurable expiry for verifier quorum info.
	ccvCache := expirable.NewLRU[verifierQuorumCacheKey, executor.CCVAddressInfo](VerifierQuorumCacheMaxEntries, nil, params.CacheExpiry)

	// Create execution attempt poller to track execution attempts
	executionAttemptPoller, err := NewEVMExecutionAttemptPoller(
		offRampAddr,
		params.ChainClient,
		logger.With(params.Lggr, "component", "ExecutionAttemptPoller"),
		0, // TODO: block number from 24 hours ago
		params.CacheExpiry,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create execution attempt poller for chain %d: %w", params.ChainSelector, err)
	}

	return &EvmDestinationReader{
		offRampCaller:          *offRamp,
		rmnRemoteCaller:        *rmnRemote,
		lggr:                   params.Lggr,
		chainSelector:          params.ChainSelector,
		client:                 params.ChainClient,
		ccvCache:               ccvCache,
		executionAttemptPoller: executionAttemptPoller,
	}, nil
}

// GetCCVSForMessage implements the DestinationReader interface. It uses the chainlink-evm client to call the get_ccvs function on the receiver contract.
// The ABI is defined here https://github.com/smartcontractkit/chainlink-ccip/blob/0e7fcfd20ab005d75d0eb863790470f91fa5b8d7/chains/evm/contracts/interfaces/IAny2EVMMessageReceiverV2.sol
func (dr *EvmDestinationReader) GetCCVSForMessage(ctx context.Context, message protocol.Message) (executor.CCVAddressInfo, error) {
	_ = ctx
	receiverAddress, sourceSelector := message.Receiver, message.SourceChainSelector

	// We need to parse out the token transfer address when caching CCV Info because it can modify the verifier quorum returned by the offramp.
	// If two messages define the same receiver, but with different tokens, they will have different CCV info. It's important to consider this when caching CCV info.
	var tokenTransferAddress common.Address
	if message.TokenTransfer != nil {
		tokenTransferAddress = common.BytesToAddress(message.TokenTransfer.DestTokenAddress)
	}

	// Try to get CCV info from cache first
	ccvInfo, found := dr.ccvCache.Peek(
		verifierQuorumCacheKey{
			sourceChainSelector:  sourceSelector,
			receiverAddress:      receiverAddress.String(),
			tokenTransferAddress: tokenTransferAddress,
		})
	if found {
		dr.lggr.Debugf("CCV info retrieved from cache for receiver %s and dest token %s on source chain %d",
			receiverAddress.String(), tokenTransferAddress.String(), sourceSelector)
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
		"destToken", tokenTransferAddress.String(),
		"chain", dr.chainSelector,
		"ccvInfo", ccvInfo,
	)

	// Store in expirable cache for future use
	dr.ccvCache.Add(
		verifierQuorumCacheKey{
			sourceChainSelector:  sourceSelector,
			receiverAddress:      receiverAddress.String(),
			tokenTransferAddress: tokenTransferAddress,
		},
		ccvInfo,
	)
	dr.lggr.Debugf("CCV info cached for receiver %s on source chain %d with token transfer address %s: %+v",
		receiverAddress.String(), sourceSelector, tokenTransferAddress.String(), ccvInfo)

	return ccvInfo, nil
}

// GetMessageExecutionState checks the destination chain to verify if a message has been executed.
func (dr *EvmDestinationReader) GetMessageExecutability(ctx context.Context, message protocol.Message) (bool, error) {
	rcv := common.BytesToAddress(message.Receiver)
	execState, err := dr.offRampCaller.GetExecutionState(
		&bind.CallOpts{
			Context: ctx,
			// TODO: Add FTF to this check
		},
		uint64(message.SourceChainSelector),
		uint64(message.SequenceNumber),
		message.Sender,
		rcv)
	if err != nil {
		// expect that the error is checked by the caller so it doesn't accidentally assume success
		return false, fmt.Errorf("failed to call getExecutionState: %w", err)
	}
	dr.lggr.Infow("getExecutionState", "messageID", message.MustMessageID(), "execState", execState)
	switch executor.MessageExecutionState(execState) {
	// We only try to execute if the message is UNTOUCHED or VERIFICATION_FAILED.
	case executor.UNTOUCHED, executor.VERIFICATION_FAILED:
		return true, nil
	}
	// All other states should not be retried and should not be executed.
	// this is for SUCCESS, IN_PROGRESS, and FAILURE.
	return false, nil
}

// GetRMNCursedSubjects gets all the cursed subjects for the destination chain including global curse.
// Used in conjunction with common.CurseChecker to persist information. This EVMReadRMNCursedSubjects is shared with verifier.
func (dr *EvmDestinationReader) GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error) {
	// We use an abstracted function to reuse code between verifier and executor.
	return rmnremotereader.EVMReadRMNCursedSubjects(ctx, dr.rmnRemoteCaller)
}

// GetExecutionAttempts retrieves execution attempts for the given message from the poller cache.
func (dr *EvmDestinationReader) GetExecutionAttempts(ctx context.Context, message protocol.Message) ([]executor.ExecutionAttempt, error) {
	return dr.executionAttemptPoller.GetExecutionAttempts(ctx, message)
}
