package destinationreader

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/rmnremotereader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
)

var (
	// Ensure EvmDestinationReader implements the DestinationReader interface.
	_ = chainaccess.DestinationReader(&EvmDestinationReader{})

	EvmDestinationReaderServiceName = "evm.destinationreader.Service"
)

type EvmDestinationReader struct {
	services.StateMachine
	cancelFunc             context.CancelFunc
	offRampCaller          offramp.OffRampCaller
	rmnRemoteCaller        rmn_remote.RMNRemoteCaller
	lggr                   logger.Logger
	client                 bind.ContractCaller
	chainSelector          protocol.ChainSelector
	executionAttemptPoller *EvmExecutionAttemptPoller
	monitoring             executor.Monitoring
}

func (dr *EvmDestinationReader) HealthReport() map[string]error {
	report := make(map[string]error)
	report[dr.Name()] = dr.Healthy()
	report[dr.executionAttemptPoller.Name()] = dr.executionAttemptPoller.Healthy()
	return report
}

type Params struct {
	Lggr                      logger.Logger
	ChainSelector             protocol.ChainSelector
	ChainClient               client.Client
	OfframpAddress            string
	RmnRemoteAddress          string
	ExecutionVisabilityWindow time.Duration
	Monitoring                executor.Monitoring
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
	appendIfNil(params.ChainClient, "chainClient")
	appendIfNil(params.Lggr, "logger")
	appendIfNil(params.ExecutionVisabilityWindow, "executionVisabilityWindow")

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

	// Create execution attempt poller to track execution attempts
	executionAttemptPoller, err := NewEVMExecutionAttemptPoller(
		offRampAddr,
		params.ChainClient,
		logger.With(params.Lggr, "component", "ExecutionAttemptPoller"),
		params.ExecutionVisabilityWindow,
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
		executionAttemptPoller: executionAttemptPoller,
		monitoring:             params.Monitoring,
	}, nil
}

func (dr *EvmDestinationReader) Start(ctx context.Context) error {
	return dr.StartOnce(EvmDestinationReaderServiceName, func() error {
		dr.lggr.Info("Starting EVM Destination Reader")
		runCtx, cancel := context.WithCancel(ctx)
		dr.cancelFunc = cancel
		err := dr.executionAttemptPoller.Start(runCtx)
		if err != nil {
			return err
		}
		dr.lggr.Info("Started EVM Destination Reader")
		return nil
	})
}

func (dr *EvmDestinationReader) Close() error {
	return dr.StopOnce(EvmDestinationReaderServiceName, func() error {
		dr.lggr.Info("Stopping EVM Destination Reader")
		err := dr.executionAttemptPoller.Close()
		if err != nil {
			return err
		}
		dr.lggr.Info("Stopped EVM Destination Reader")
		return nil
	})
}

func (dr *EvmDestinationReader) Name() string {
	return strings.Join([]string{dr.chainSelector.String(), EvmDestinationReaderServiceName}, ".")
}

// GetCCVSForMessage implements the DestinationReader interface. It uses the chainlink-evm client to call the get_ccvs function on the receiver contract.
// The ABI is defined here https://github.com/smartcontractkit/chainlink-ccip/blob/0e7fcfd20ab005d75d0eb863790470f91fa5b8d7/chains/evm/contracts/interfaces/IAny2EVMMessageReceiverV2.sol
//
// If the OffRamp reverts with custom error 0x97a63cd9, the revert data is (address, uint256, uint256): typically
// (receiverOrVerifier, requiredCount, actualCount). It usually means the receiver's CCV requirements could not be
// resolved (e.g. receiver not set, message token/receiver mismatch, or view reverted). Check that the message's
// receiver and token transfer match a deployed receiver contract that implements get_ccvs.
func (dr *EvmDestinationReader) GetCCVSForMessage(ctx context.Context, message protocol.Message) (protocol.CCVAddressInfo, error) {
	receiverAddress, sourceSelector := message.Receiver, message.SourceChainSelector

	// We need to parse out the token transfer address when caching CCV Info because it can modify the verifier quorum returned by the offramp.
	// If two messages define the same receiver, but with different tokens, they will have different CCV info. It's important to consider this when caching CCV info.
	var tokenTransferAddress common.Address
	if message.TokenTransfer != nil {
		tokenTransferAddress = common.BytesToAddress(message.TokenTransfer.DestTokenAddress)
	}

	encodedMsg, err := message.Encode()
	if err != nil {
		return protocol.CCVAddressInfo{}, fmt.Errorf("failed to encode message: %w", err)
	}

	start := time.Now()
	chainCCVInfo, err := dr.offRampCaller.GetCCVsForMessage(&bind.CallOpts{Context: ctx}, encodedMsg)
	if err != nil {
		dr.monitoring.Metrics().IncrementOfframpGetCCVsForMessageFailure(ctx, dr.chainSelector)
		return protocol.CCVAddressInfo{}, fmt.Errorf("failed to call GetCCVSForMessage: %w", err)
	}
	// record only successful calls for clean distribution
	dr.monitoring.Metrics().RecordOfframpGetCCVsForMessageLatency(ctx, time.Since(start), dr.chainSelector)

	req, opt, optThreshold := chainCCVInfo.RequiredCCVs, chainCCVInfo.OptionalCCVs, chainCCVInfo.Threshold

	requiredCCVs := make([]protocol.UnknownAddress, 0)
	optionalCCVs := make([]protocol.UnknownAddress, 0)
	for _, addr := range req {
		requiredCCVs = append(requiredCCVs, protocol.UnknownAddress(addr.Bytes()))
	}

	for _, addr := range opt {
		optionalCCVs = append(optionalCCVs, protocol.UnknownAddress(addr.Bytes()))
	}

	ccvInfo := protocol.CCVAddressInfo{
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

	return ccvInfo, nil
}

// GetMessageSuccess checks the destination chain to verify if a message has been executed successfully.
func (dr *EvmDestinationReader) GetMessageSuccess(ctx context.Context, message protocol.Message) (bool, error) {
	execState, err := dr.offRampCaller.GetExecutionState(
		&bind.CallOpts{
			Context: ctx,
			// TODO: Add FTF to this check
		},
		message.MustMessageID(),
	)
	if err != nil {
		// expect that the error is checked by the caller so it doesn't accidentally assume success
		return false, fmt.Errorf("failed to call getExecutionState: %w", err)
	}

	dr.lggr.Infow("getExecutionState", "messageID", message.MustMessageID(), "execState", execState)
	if executor.MessageExecutionState(execState) == executor.SUCCESS {
		return true, nil
	}

	return false, nil
}

// GetRMNCursedSubjects gets all the cursed subjects for the destination chain including global curse.
// Used in conjunction with common.CurseChecker to persist information. This EVMReadRMNCursedSubjects is shared with verifier.
func (dr *EvmDestinationReader) GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error) {
	// We use an abstracted function to reuse code between verifier and executor.
	return rmnremotereader.EVMReadRMNCursedSubjects(ctx, dr.rmnRemoteCaller)
}

// GetExecutionAttempts retrieves execution attempts for the given message from the poller cache.
func (dr *EvmDestinationReader) GetExecutionAttempts(ctx context.Context, message protocol.Message) ([]protocol.ExecutionAttempt, error) {
	return dr.executionAttemptPoller.GetExecutionAttempts(ctx, message)
}
