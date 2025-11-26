package executor

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Ensure ChainlinkExecutor implements the Executor interface.
var _ executor.Executor = &ChainlinkExecutor{}

type ChainlinkExecutor struct {
	lggr                   logger.Logger
	contractTransmitters   map[protocol.ChainSelector]executor.ContractTransmitter
	destinationReaders     map[protocol.ChainSelector]executor.DestinationReader
	curseChecker           common.CurseChecker
	verifierResultsReader  executor.VerifierResultReader
	monitoring             executor.Monitoring
	defaultExecutorAddress map[protocol.ChainSelector]protocol.UnknownAddress
}

func NewChainlinkExecutor(
	lggr logger.Logger,
	contractTransmitters map[protocol.ChainSelector]executor.ContractTransmitter,
	destinationReaders map[protocol.ChainSelector]executor.DestinationReader,
	curseChecker common.CurseChecker,
	verifierResultReader executor.VerifierResultReader,
	monitoring executor.Monitoring,
	defaultExecutorAddress map[protocol.ChainSelector]protocol.UnknownAddress,
) *ChainlinkExecutor {
	return &ChainlinkExecutor{
		lggr:                   lggr,
		contractTransmitters:   contractTransmitters,
		destinationReaders:     destinationReaders,
		curseChecker:           curseChecker,
		verifierResultsReader:  verifierResultReader,
		monitoring:             monitoring,
		defaultExecutorAddress: defaultExecutorAddress,
	}
}

func (cle *ChainlinkExecutor) CheckValidMessage(ctx context.Context, message protocol.Message) error {
	destinationChain := message.DestChainSelector
	_, ok := cle.destinationReaders[destinationChain]
	if !ok {
		return fmt.Errorf("no destination reader for chain %d", destinationChain)
	}
	_, ok = cle.contractTransmitters[destinationChain]
	if !ok {
		return fmt.Errorf("no contract transmitter for chain %d", destinationChain)
	}
	return nil
}

// AttemptExecuteMessage will try to get all supplementary information for a message required for execution, then attempt the execution.
// If not all supplementary information is available (ie not enough verifierResults) it will return an error and the message will not be attempted.
func (cle *ChainlinkExecutor) AttemptExecuteMessage(ctx context.Context, message protocol.Message) error {
	destinationChain := message.DestChainSelector
	messageID, err := message.MessageID()
	if err != nil {
		return fmt.Errorf("failed to get message ID: %w", err)
	}

	// Fetch CCV data from the indexer and CCV info from the destination reader
	// concurrently.
	g, errGroupCtx := errgroup.WithContext(ctx)
	ccvData := make([]protocol.VerifierResult, 0)
	g.Go(func() error {
		res, err := cle.verifierResultsReader.GetVerifierResults(errGroupCtx, messageID)
		if err != nil {
			return fmt.Errorf("failed to get Verifier Results for message %s: %w", messageID.String(), err)
		}

		for _, r := range res {
			if !r.MessageExecutorAddress.Equal(cle.defaultExecutorAddress[destinationChain]) {
				return fmt.Errorf("messageID %s did not specify our executor %s", messageID.String(), cle.defaultExecutorAddress[destinationChain].String())
			}
			// should we also validate messageID and other fields from the verifier result?
			ccvData = append(ccvData, r)
		}
		return nil
	})

	var ccvInfo executor.CCVAddressInfo
	g.Go(func() error {
		res, err := cle.destinationReaders[destinationChain].GetCCVSForMessage(
			errGroupCtx,
			message,
		)
		if err != nil && len(res.RequiredCCVs) == 0 {
			return fmt.Errorf("failed to get Verifier Quorum info for message %s: %w", messageID.String(), err)
		}
		ccvInfo = res
		return nil
	})

	if err := g.Wait(); err != nil {
		return err
	}

	// Order the Verifier Results to match the order expected by the receiver contract.
	cle.lggr.Infow("got ccv info and verifier results for message",
		"messageID", messageID,
		"destinationChain", destinationChain,
		"verifierQuorum", ccvInfo,
		"ccvDatasLen", len(ccvData),
		"ccvDatasDestVerifiers", ccvDataDestVerifiers(ccvData),
		"ccvDatasSourceVerifiers", ccvDataSourceVerifiers(ccvData),
	)
	orderedCCVData, orderedCCVOfframps, latestCCVTimestamp, err := orderCCVData(ccvData, ccvInfo)
	if err != nil {
		return fmt.Errorf("failed to order CCV Offramp data for message %s: %w", messageID.String(), err)
	}

	// Create the aggregated report and transmit it to the chain.
	aggregatedReport := executor.AbstractAggregatedReport{
		CCVS:    orderedCCVOfframps,
		CCVData: orderedCCVData,
		Message: message,
	}
	cle.lggr.Infow("transmitting aggregated report to chain",
		"messageID", messageID,
		"destinationChain", destinationChain,
		"latestCCVTimestamp", latestCCVTimestamp,
		"aggregatedReport", aggregatedReport,
	)
	err = cle.contractTransmitters[destinationChain].ConvertAndWriteMessageToChain(ctx, aggregatedReport)
	if err != nil {
		return fmt.Errorf("failed to transmit message %s to chain %d: %w", messageID.String(), destinationChain, err)
	}

	// Record the message execution latency.
	cle.monitoring.Metrics().RecordMessageExecutionLatency(ctx, time.Since(time.Unix(latestCCVTimestamp, 0)))

	return nil
}

func ccvDataDestVerifiers(ccvDatas []protocol.VerifierResult) []string {
	destVerifiersSet := make(map[string]struct{})
	for _, ccvData := range ccvDatas {
		destVerifiersSet[ccvData.VerifierDestAddress.String()] = struct{}{}
	}

	destVerifiers := make([]string, 0, len(destVerifiersSet))
	for verifier := range destVerifiersSet {
		destVerifiers = append(destVerifiers, verifier)
	}
	return destVerifiers
}

func ccvDataSourceVerifiers(ccvDatas []protocol.VerifierResult) []string {
	sourceVerifiersSet := make(map[string]struct{})
	for _, ccvData := range ccvDatas {
		// MessageCCVAddresses contains the source verifier addresses
		// Collect all unique source verifiers
		for _, addr := range ccvData.MessageCCVAddresses {
			sourceVerifiersSet[addr.String()] = struct{}{}
		}
	}

	sourceVerifiers := make([]string, 0, len(sourceVerifiersSet))
	for verifier := range sourceVerifiersSet {
		sourceVerifiers = append(sourceVerifiers, verifier)
	}
	return sourceVerifiers
}

// orderCCVData orders the CCV data retrieved from the indexer to match the order expected
// by the receiver contract. It validates that all required CCVs are present and
// that the number of optional CCVs is sufficient. It also determines the latest
// timestamp among all CCV datas for monitoring purposes.
func orderCCVData(
	ccvDatas []protocol.VerifierResult,
	receiverCCVInfo executor.CCVAddressInfo,
) (
	orderedCCVData [][]byte,
	orderedCCVOfframps []protocol.UnknownAddress,
	latestCCVTimestamp int64,
	err error,
) {
	orderedCCVData = make([][]byte, 0, len(ccvDatas))
	orderedCCVOfframps = make([]protocol.UnknownAddress, 0, len(ccvDatas))

	// Map the destination verifier addresses to the CCV data associated with them.
	// This is to facilitate fast lookups in the loops below.
	destVerifierToCCVData := make(map[string]protocol.VerifierResult)
	for _, ccvData := range ccvDatas {
		destVerifierToCCVData[ccvData.VerifierDestAddress.String()] = ccvData
	}

	// Check that all the required CCVs are present in the CCV data retrieved.
	var lastRequiredCCVTimestamp int64
	for _, ccvAddress := range receiverCCVInfo.RequiredCCVs {
		data, ok := destVerifierToCCVData[ccvAddress.String()]
		if !ok {
			// required CCV not found, can't execute.
			return nil, nil, 0, errors.Join(
				executor.ErrInsufficientVerifiers,
				fmt.Errorf("required CCV (%s) not found from ccv data retrieved (%+v), required: %+v",
					ccvAddress.String(),
					slices.Collect(maps.Keys(destVerifierToCCVData)),
					toStrSlice(receiverCCVInfo.RequiredCCVs),
				),
			)
		}

		orderedCCVData = append(orderedCCVData, data.CCVData)
		orderedCCVOfframps = append(orderedCCVOfframps, ccvAddress)
		lastRequiredCCVTimestamp = max(lastRequiredCCVTimestamp, data.Timestamp.UnixMilli())
	}

	// Check which optional CCVs are present in the CCV data retrieved.
	optionalCount := 0
	optionalCCVTimestamps := make([]int64, 0, len(receiverCCVInfo.OptionalCCVs))
	for _, ccvAddress := range receiverCCVInfo.OptionalCCVs {
		if optionalCount >= int(receiverCCVInfo.OptionalThreshold) {
			break
		}
		data, ok := destVerifierToCCVData[ccvAddress.String()]
		if !ok {
			// optional CCV not found, but there may be others still.
			continue
		}

		// optional CCV found, add to the ordered lists.
		orderedCCVData = append(orderedCCVData, data.CCVData)
		orderedCCVOfframps = append(orderedCCVOfframps, ccvAddress)
		optionalCCVTimestamps = append(optionalCCVTimestamps, data.Timestamp.UnixMilli())
		optionalCount++
	}

	// check if we have enough optional CCVs.
	if optionalCount < int(receiverCCVInfo.OptionalThreshold) {
		return nil, nil, 0, errors.Join(
			executor.ErrInsufficientVerifiers,
			fmt.Errorf(
				"not enough optional CCVs found (%d) from ccv data retrieved (%+v) (required threshold: %d, optional ccvs: %+v)",
				optionalCount,
				slices.Collect(maps.Keys(destVerifierToCCVData)),
				receiverCCVInfo.OptionalThreshold,
				toStrSlice(receiverCCVInfo.OptionalCCVs),
			),
		)
	}

	// metrics: determine the latest timestamp of all the CCV datas.
	if receiverCCVInfo.OptionalThreshold > 0 {
		slices.Sort(optionalCCVTimestamps)
		minSignificantOptionalCCVTimestamp := optionalCCVTimestamps[receiverCCVInfo.OptionalThreshold-1]
		latestCCVTimestamp = max(lastRequiredCCVTimestamp, minSignificantOptionalCCVTimestamp)
	} else {
		latestCCVTimestamp = lastRequiredCCVTimestamp
	}

	return orderedCCVData, orderedCCVOfframps, latestCCVTimestamp, nil
}

func toStrSlice[T fmt.Stringer](slice []T) []string {
	res := make([]string, len(slice))
	for i, item := range slice {
		res[i] = item.String()
	}
	return res
}

func (cle *ChainlinkExecutor) Validate() error {
	if cle.lggr == nil {
		return fmt.Errorf("logger is required")
	}
	chainSetA := make(map[protocol.ChainSelector]struct{})
	chainSetB := make(map[protocol.ChainSelector]struct{})
	if cle.contractTransmitters == nil {
		return fmt.Errorf("contract transmitters is required")
	}
	if cle.destinationReaders == nil {
		return fmt.Errorf("destination readers is required")
	}
	for chainSel := range cle.contractTransmitters {
		chainSetA[chainSel] = struct{}{}
	}

	for chainSel := range cle.destinationReaders {
		chainSetB[chainSel] = struct{}{}
	}
	if len(chainSetA) == 0 {
		return fmt.Errorf("contract transmitters must support at least one chain")
	}
	if len(chainSetB) == 0 {
		return fmt.Errorf("destination readers must support at least one chain")
	}

	if len(chainSetA) != len(chainSetB) {
		return fmt.Errorf("contract transmitters and destination readers must support the same chains")
	}
	for chainID := range chainSetA {
		if _, ok := chainSetB[chainID]; !ok {
			return fmt.Errorf("contract transmitters and destination readers must support the same chains")
		}
	}
	return nil
}

// GetMessageStatus checks if a message should be executed and/or retried.
// Returns (shouldRetry bool, shouldExecute bool, error) to indicate whether the message should be retried (added back to heap) and executed.
func (cle *ChainlinkExecutor) GetMessageStatus(ctx context.Context, message protocol.Message) (executor.MessageStatusResults, error) {
	messageID, err := message.MessageID()
	if err != nil {
		return executor.MessageStatusResults{}, fmt.Errorf("failed to get message ID: %w", err)
	}
	cursed := cle.curseChecker.IsRemoteChainCursed(ctx, message.DestChainSelector, message.SourceChainSelector)
	if cursed {
		cle.lggr.Infow("skipping execution for message due to curse", "messageID", messageID, "cursed", cursed)
		return executor.MessageStatusResults{ShouldRetry: true, ShouldExecute: false}, nil
	}
	return cle.GetExecutionState(ctx, message, messageID)
}

// GetExecutionState checks the onchain execution state of a message and returns if it should be retried and executed.
// It does not do any checks to determine if verifications are available or not.
// Note these states might not be applicable for nonevm integrations. Should we add a translation layer or move them to destination reader?
// UNTOUCHED: Message should be executed and retried later to confirm successful execution
// IN_PROGRESS: Message reentrancy protection, should not be retried, should not be executed.
// SUCCESS: Message was executed successfully, don't retry and don't execute.
// FAILURE: Message failed to execute due to invalid verifier, don't retry and don't execute.
func (cle *ChainlinkExecutor) GetExecutionState(ctx context.Context, message protocol.Message, id protocol.Bytes32) (ret executor.MessageStatusResults, err error) {
	// Check if the message is already executed to not waste gas and time.
	destinationChain := message.DestChainSelector

	executionState, err := cle.destinationReaders[destinationChain].GetMessageExecutionState(
		ctx,
		message,
	)
	if err != nil {
		// If we can't get execution state, don't execute, but put back in heap to retry later.
		return executor.MessageStatusResults{ShouldRetry: true, ShouldExecute: false}, fmt.Errorf("failed to check GetMessageExecutionState: %w", err)
	}
	switch executionState {
	// We only retry and execute if the message is UNTOUCHED.
	case executor.UNTOUCHED:
		ret.ShouldRetry = true
		ret.ShouldExecute = true
		err = nil

	// All other states should not be retried and should not be executed.
	// this is for SUCCESS, IN_PROGRESS, and FAILURE.
	default:
		ret.ShouldRetry = false
		ret.ShouldExecute = false
		err = nil
	}

	cle.lggr.Infow("message status",
		"messageID", id,
		"executionState", executionState,
		"shouldRetry", ret.ShouldRetry,
		"shouldExecute", ret.ShouldExecute,
	)

	return ret, err
}
