package executor

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

// Ensure ChainlinkExecutor implements the Executor interface.
var _ executor.Executor = &ChainlinkExecutor{}

const chainlinkExecutorServiceName = "chainlink.executor.Service"

// ChainlinkExecutor is responsible for managing the execution of a single message once it's been marked
// for execution by the Coordinator. It goes through a series of steps and checks before finally transmitting.
// Depending on these checks, it may send the message back to the coordinator for retry later.
type ChainlinkExecutor struct {
	services.StateMachine
	services.Service
	lggr                   logger.Logger
	contractTransmitters   map[protocol.ChainSelector]chainaccess.ContractTransmitter
	destinationReaders     map[protocol.ChainSelector]chainaccess.DestinationReader
	readerServices         []services.Service
	curseChecker           common.CurseChecker
	verifierResultsReader  executor.VerifierResultReader
	leaderElector          executor.LeaderElector
	monitoring             monitoring.Monitoring
	defaultExecutorAddress map[protocol.ChainSelector]protocol.UnknownAddress
}

func NewChainlinkExecutor(
	lggr logger.Logger,
	contractTransmitters map[protocol.ChainSelector]chainaccess.ContractTransmitter,
	destinationReaders map[protocol.ChainSelector]chainaccess.DestinationReader,
	curseChecker common.CurseChecker,
	verifierResultReader executor.VerifierResultReader,
	leaderElector executor.LeaderElector,
	monitoring monitoring.Monitoring,
	defaultExecutorAddress map[protocol.ChainSelector]protocol.UnknownAddress,
) *ChainlinkExecutor {
	lggr.Infow("new chainlink executor",
		"defaultExecutorAddress", defaultExecutorAddress,
	)

	var readerServices []services.Service
	for _, reader := range destinationReaders {
		if svc, ok := reader.(services.Service); ok {
			readerServices = append(readerServices, svc)
		}
	}

	return &ChainlinkExecutor{
		lggr:                   lggr,
		contractTransmitters:   contractTransmitters,
		destinationReaders:     destinationReaders,
		readerServices:         readerServices,
		curseChecker:           curseChecker,
		verifierResultsReader:  verifierResultReader,
		leaderElector:          leaderElector,
		monitoring:             monitoring,
		defaultExecutorAddress: defaultExecutorAddress,
	}
}

func (cle *ChainlinkExecutor) Start(ctx context.Context) error {
	return cle.StartOnce(chainlinkExecutorServiceName, func() error {
		cle.lggr.Info("Starting Chainlink Executor")
		var startedServices []services.Service
		var startErrs []error
		for _, svc := range cle.readerServices {
			if err := svc.Start(ctx); err != nil {
				startErrs = append(startErrs, fmt.Errorf("failed to start destination reader service %s: %w", svc.Name(), err))
			} else {
				startedServices = append(startedServices, svc)
			}
		}
		if len(startErrs) > 0 {
			for _, svc := range startedServices {
				if closeErr := svc.Close(); closeErr != nil {
					startErrs = append(startErrs, closeErr)
				}
			}
			return errors.Join(startErrs...)
		}
		return nil
	})
}

func (cle *ChainlinkExecutor) Close() error {
	return cle.StopOnce(chainlinkExecutorServiceName, func() error {
		cle.lggr.Info("Stopping Chainlink Executor")
		var errs []error
		for _, svc := range cle.readerServices {
			if err := svc.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to close destination reader service %s: %w", svc.Name(), err))
			}
		}
		cle.lggr.Info("Stopped Chainlink Executor")
		if len(errs) > 0 {
			return errors.Join(errs...)
		}
		return nil
	})
}

func (cle *ChainlinkExecutor) HealthReport() map[string]error {
	report := make(map[string]error)
	report[cle.Name()] = cle.Ready()

	for _, svc := range cle.readerServices {
		services.CopyHealth(report, svc.HealthReport())
	}

	return report
}

func (cle *ChainlinkExecutor) Name() string {
	return chainlinkExecutorServiceName
}

func (cle *ChainlinkExecutor) Ready() error {
	if err := cle.StateMachine.Ready(); err != nil {
		return err
	}
	if n := len(cle.destinationReaders); n > 0 && cle.readyDestinationReaders() == 0 {
		return fmt.Errorf("no destination reader is ready across %d chain(s)", n)
	}
	return nil
}

// Degraded names each destination chain whose reader is not ready (for example its
// RPC is unreachable); nil when all are. Consulted only when Ready passes, so at
// least one reader is usable.
func (cle *ChainlinkExecutor) Degraded() error {
	var errs []error
	for _, sel := range slices.Sorted(maps.Keys(cle.destinationReaders)) {
		if !cle.destinationReaders[sel].IsReady(sel) {
			errs = append(errs, fmt.Errorf("DestinationReader[%d]: not ready", sel))
		}
	}
	return errors.Join(errs...)
}

func (cle *ChainlinkExecutor) readyDestinationReaders() int {
	ready := 0
	for sel, reader := range cle.destinationReaders {
		if reader.IsReady(sel) {
			ready++
		}
	}
	return ready
}

func (cle *ChainlinkExecutor) CheckValidMessage(ctx context.Context, message protocol.Message) error {
	destinationChain := message.DestChainSelector
	reader, ok := cle.destinationReaders[destinationChain]
	if !ok {
		return fmt.Errorf("no destination reader for chain %d", destinationChain)
	}
	_, ok = cle.contractTransmitters[destinationChain]
	if !ok {
		return fmt.Errorf("no contract transmitter for chain %d", destinationChain)
	}
	if err := reader.CheckHealth(destinationChain); err != nil {
		cle.metricsForMessage(message).IncrementDestinationReaderCriticalFailure(ctx, destinationChain)
		return fmt.Errorf("destination reader critically failed for chain %d: %w", destinationChain, errors.Join(err, executor.ErrDestinationReaderUnhealthy))
	}
	return nil
}

// HandleMessage will process a single message through the executors and its components.
// 1. Check curse using the curse checker.
// 2. Check executability using the destination reader. Executability checks on chain execution state.
// 3. Get additional data (verifier results and quorum)
// 4. Confirm the additional data is sufficient for execution.
// 5. Order the CCV data to match the order expected by the receiver contract.
// 6. Create the aggregated report and transmit it to the chain.
func (cle *ChainlinkExecutor) HandleMessage(ctx context.Context, message protocol.Message) (shouldRetry bool, err error) {
	span := oteltrace.SpanFromContext(ctx)
	metrics := cle.metricsForMessage(message)

	// Check prerequisites to avoid toctou issues
	if err := cle.CheckValidMessage(ctx, message); err != nil {
		span.AddEvent(monitoring.EventInvalidMessageSkipped)
		if errors.Is(err, executor.ErrDestinationReaderUnhealthy) {
			// Transient destination reader health failure: retry the message later.
			return true, err
		}
		return false, err
	}
	start := time.Now()
	destinationChain := message.DestChainSelector
	messageID := message.MustMessageID()

	cursed, curseErr := cle.curseChecker.IsRemoteChainCursed(ctx, message.DestChainSelector, message.SourceChainSelector)
	if cursed {
		if curseErr != nil {
			cle.lggr.Warnw("delaying execution - curse state unknown", protocol.LogKeyMessageID, messageID, "error", curseErr)
			span.RecordError(curseErr)
			span.AddEvent(monitoring.EventDelayedCurseStateUnknown)
		} else {
			cle.lggr.Debugw("delaying execution due to curse", protocol.LogKeyMessageID, messageID)
			span.AddEvent(monitoring.EventDelayedCursed)
		}
		reason := monitoring.MessageTransitionReasonRemoteChainCursed
		if curseErr != nil {
			reason = monitoring.MessageTransitionReasonCurseStateUnknown
		}
		metrics.IncrementMessageTransition(ctx, monitoring.MessageTransitionStageExecution, monitoring.MessageTransitionOutcomeSkipped, reason)
		return true, nil
	}

	executionSuccess, err := cle.destinationReaders[destinationChain].GetMessageSuccess(ctx, message)
	if err != nil {
		// If we can't get execution state, don't execute, but put back in heap to retry later.
		// this usually only happens due to rpc issues, other nodes will try and this node will expect to see status SUCCESS later.
		cle.lggr.Warnw("delaying execution due to failed check GetMessageExecutionState", protocol.LogKeyMessageID, messageID)
		span.RecordError(err)
		span.AddEvent(monitoring.EventDelayedExecutionStateUnknown)
		metrics.IncrementMessageFailure(ctx, monitoring.MessageTransitionStageExecution, true, monitoring.MessageFailureClassExecutionStateRead)
		return true, err
	}
	if executionSuccess {
		cle.lggr.Debugw("skipping execution due to already being successfully executed", protocol.LogKeyMessageID, messageID)
		metrics.IncrementAlreadyExecutedMessages(ctx)
		metrics.IncrementMessageTransition(ctx, monitoring.MessageTransitionStageExecution, monitoring.MessageTransitionOutcomeSkipped, monitoring.MessageTransitionReasonAlreadyExecuted)
		span.AddEvent(monitoring.EventAlreadyExecuted)
		return false, nil
	}

	verifierResults, verifierQuorum, err := cle.getVerifierResultsAndQuorum(ctx, message, messageID)
	if err != nil {
		cle.lggr.Warnw("delaying execution due to failed request for verifier results and quorum", protocol.LogKeyMessageID, messageID)
		metrics.IncrementMessageFailure(ctx, monitoring.MessageTransitionStageExecution, true, monitoring.MessageFailureClassVerificationDataRead)
		return true, err
	}
	if len(verifierResults) == 0 {
		noResultsErr := fmt.Errorf("delaying execution due to no verifier results %s", messageID.String())
		metrics.IncrementMessageTransition(ctx, monitoring.MessageTransitionStageExecution, monitoring.MessageTransitionOutcomeSkipped, monitoring.MessageTransitionReasonNoVerifierResults)
		return true, noResultsErr
	}

	// Order the Verifier Results to match the order expected by the receiver contract.
	cle.lggr.Debugw("got ccv info and verifier results",
		protocol.LogKeyMessageID, messageID,
		protocol.LogKeyDestChain, destinationChain,
		"verifierQuorum", verifierQuorum,
		"verifierResultsLen", len(verifierResults),
		"verifierResultsDestVerifiers", ccvDataDestVerifiers(verifierResults),
		"verifierResultsSourceVerifiers", ccvDataSourceVerifiers(verifierResults),
	)

	// if a receiver expects more CCVs than the source message defined, we will never be able to execute.
	// we've validated that VerifierResults are consistent in their ccv address fields, so we only need to check the first result for this check.
	if len(verifierQuorum.RequiredCCVs)+int(verifierQuorum.OptionalThreshold) > len(verifierResults[0].MessageCCVAddresses) {
		// PER-MESSAGE LOG (failure): terminal; receiver quorum can never be satisfied, no retry.
		cle.lggr.Infow("skipping execution and not retrying due to impossible receiver verifier quorum", protocol.LogTypeKey, protocol.LogTypeMessageFailure, protocol.LogKeyMessageID, messageID)
		metrics.IncrementUnrecoverableMessageFailure(ctx)
		metrics.IncrementMessageFailure(ctx, monitoring.MessageTransitionStageExecution, false, monitoring.MessageFailureClassQuorumImpossible)
		span.AddEvent(monitoring.EventUnrecoverableQuorumImpossible)
		return false, nil
	}

	orderedverifierResults, orderedCCVOfframps, latestCCVTimestamp, err := orderCCVData(verifierResults, verifierQuorum)
	if err != nil {
		cle.lggr.Warnw("message did not meet verifier quorum, will retry", protocol.LogKeyMessageID, messageID)
		metrics.IncrementMessageFailure(ctx, monitoring.MessageTransitionStageExecution, true, monitoring.MessageFailureClassQuorumNotMet)
		return true, err
	}

	if !cle.destinationReaders[destinationChain].IsReady(destinationChain) {
		cle.lggr.Debugw("execution attempt poller not ready, will retry",
			protocol.LogKeyMessageID, messageID)
		span.AddEvent(monitoring.EventDelayedPollerNotReady)
		metrics.IncrementMessageTransition(ctx, monitoring.MessageTransitionStageExecution, monitoring.MessageTransitionOutcomeSkipped, monitoring.MessageTransitionReasonPollerNotReady)
		return true, nil
	}

	// Check if anyone (third-party or other executor) has honestly attempted to execute this message.
	// If they haven't we can execute it.
	attemptCheck, err := cle.destinationReaders[destinationChain].HasHonestAttempt(ctx, message, verifierResults, verifierQuorum)
	if err != nil {
		cle.lggr.Errorw("unable to call execution checker, will retry message", "error", err, protocol.LogKeyMessageID, messageID)
		metrics.IncrementMessageFailure(ctx, monitoring.MessageTransitionStageExecution, true, monitoring.MessageFailureClassHonestAttemptCheck)
		return true, err
	}

	// Do not transmit over an honest attempt. Recheck successful attempts so reorg removal can
	// reopen execution; deterministic receiver failures remain terminal.
	if attemptCheck.Honest {
		cle.lggr.Debugw("skipping execution due to existing honest attempt", protocol.LogKeyMessageID, messageID)
		span.AddEvent(monitoring.EventSkippedHonestAttemptExists)
		metrics.IncrementMessageTransition(ctx, monitoring.MessageTransitionStageExecution, monitoring.MessageTransitionOutcomeSkipped, monitoring.MessageTransitionReasonHonestAttempt)
		return !attemptCheck.HonestAttemptFailed, nil
	}

	// An attempt that is not honest does not stop the pool, but only the first ranked executor may send after it.
	if attemptCheck.NotHonestAttemptExists {
		firstRanked, err := cle.leaderElector.IsFirstRanked(messageID, destinationChain)
		if err != nil {
			cle.lggr.Errorw("leader elector failed for retry decision, will retry message", "error", err, protocol.LogKeyMessageID, messageID)
			metrics.IncrementMessageFailure(ctx, monitoring.MessageTransitionStageExecution, true, monitoring.MessageFailureClassHonestAttemptCheck)
			return true, err
		}
		if !firstRanked {
			cle.lggr.Debugw("skipping execution after attempt that is not honest, this executor is not the first ranked", protocol.LogKeyMessageID, messageID)
			span.AddEvent(monitoring.EventSkippedNotDesignatedRetrier)
			metrics.IncrementMessageTransition(ctx, monitoring.MessageTransitionStageExecution, monitoring.MessageTransitionOutcomeSkipped, monitoring.MessageTransitionReasonNotRetrier)
			return false, nil
		}
	}

	// Create the aggregated report and transmit it to the chain.
	aggregatedReport := protocol.AbstractAggregatedReport{
		CCVS:    orderedCCVOfframps,
		CCVData: orderedverifierResults,
		Message: message,
	}
	// Full report dumped at Debug to keep the per-message success line small.
	cle.lggr.Debugw("aggregated report", protocol.LogKeyMessageID, messageID, "aggregatedReport", aggregatedReport)
	err = cle.contractTransmitters[destinationChain].ConvertAndWriteMessageToChain(ctx, aggregatedReport)
	if err != nil {
		if errors.Is(err, executor.ErrMessageEncoding) {
			metrics.IncrementUnrecoverableMessageFailure(ctx)
			metrics.IncrementMessageFailure(ctx, monitoring.MessageTransitionStageExecution, false, monitoring.MessageFailureClassMessageEncoding)
			cle.lggr.Warnw("skipping retry due to message encoding error", protocol.LogKeyMessageID, messageID, "error", err)
			return false, err
		}
		if errors.Is(err, executor.ErrMessageRejectedByTransmitter) {
			metrics.IncrementUnrecoverableMessageFailure(ctx)
			metrics.IncrementMessageFailure(ctx, monitoring.MessageTransitionStageExecution, false, monitoring.MessageFailureClassTransmitterRejected)
			cle.lggr.Warnw("skipping retry due to terminal transmitter rejection", protocol.LogKeyMessageID, messageID, "error", err)
			return false, err
		}
		cle.lggr.Warnw("will retry execution due to failed ConvertAndWriteMessageToChain", protocol.LogKeyMessageID, messageID)
		metrics.IncrementMessageFailure(ctx, monitoring.MessageTransitionStageExecution, true, monitoring.MessageFailureClassTransmission)
		return true, fmt.Errorf("%w: %w", executor.ErrExecutionContended, err)
	}

	// PER-MESSAGE LOG (success): one per message, when this executor transmits to chain.
	cle.lggr.Infow("transmitting aggregated report to chain",
		protocol.LogTypeKey, protocol.LogTypeMessageSuccess,
		protocol.LogKeyMessageID, messageID,
		protocol.LogKeyDestChain, destinationChain,
		"latestCCVTimestamp", latestCCVTimestamp,
		"verifierQuorum", verifierQuorum,
		"verifierResultsLen", len(verifierResults),
	)

	// Record the message execution latency.
	metrics.RecordMessageExecutionLatency(ctx, time.Since(start), destinationChain)
	metrics.IncrementMessageTransition(ctx, monitoring.MessageTransitionStageExecution, monitoring.MessageTransitionOutcomeSucceeded, monitoring.MessageTransitionReasonNone)

	span.AddEvent(monitoring.EventMessageTransmitted, oteltrace.WithAttributes(
		attribute.Int64(tracing.LatestCCVTimestampKey, latestCCVTimestamp),
	))

	return false, nil
}

func (cle *ChainlinkExecutor) getVerifierResultsAndQuorum(ctx context.Context, message protocol.Message, messageID protocol.Bytes32) ([]protocol.VerifierResult, protocol.CCVAddressInfo, error) {
	destinationChain, sourceSelector := message.DestChainSelector, message.SourceChainSelector

	// Fetch CCV data from the indexer and CCV info from the destination reader concurrently.
	g, errGroupCtx := errgroup.WithContext(ctx)
	ccvData := make([]protocol.VerifierResult, 0)
	g.Go(func() error {
		res, err := cle.verifierResultsReader.GetVerifierResults(errGroupCtx, messageID)
		if err != nil {
			return fmt.Errorf("failed to get Verifier Results for message %s: %w", messageID.String(), err)
		}

		for _, r := range res {
			if !r.MessageExecutorAddress.Equal(cle.defaultExecutorAddress[sourceSelector]) {
				cle.lggr.Warnw("Verifier Result did not specify our executor",
					"verifierResult", r,
					"defaultExecutorAddress", cle.defaultExecutorAddress[sourceSelector].String(),
				)
				// continue here because it's possible to still meet verifier quorum with some invalid verifier results.
				continue
			}
			if err := r.ValidateFieldsConsistent(); err != nil {
				cle.lggr.Warnw("Verifier Result fields are inconsistent",
					"verifierResult", r,
					"error", err,
				)
				// continue here because it's possible to still meet verifier quorum with some invalid verifier results.
				continue
			}
			if r.MessageID != messageID {
				cle.lggr.Warnw("Verifier Result message ID does not match requested message ID",
					"verifierResult", r,
					"expectedMessageID", messageID.String(),
				)
				continue
			}
			ccvData = append(ccvData, r)
		}
		return nil
	})

	var ccvInfo protocol.CCVAddressInfo
	g.Go(func() error {
		res, err := cle.destinationReaders[destinationChain].GetCCVSForMessage(
			errGroupCtx,
			message,
		)
		if err != nil {
			return fmt.Errorf("failed to get Verifier Quorum for message %s: %w", messageID.String(), err)
		}
		ccvInfo = res
		return nil
	})

	if err := g.Wait(); err != nil {
		return ccvData, ccvInfo, err
	}
	return ccvData, ccvInfo, nil
}

func (cle *ChainlinkExecutor) metricsForMessage(message protocol.Message) monitoring.MetricLabeler {
	return cle.monitoring.Metrics().With(
		"source_chain_selector", message.SourceChainSelector.String(),
		"source_chain_name", message.SourceChainSelector.ChainName(),
		"dest_chain_selector", message.DestChainSelector.String(),
		"dest_chain_name", message.DestChainSelector.ChainName(),
	)
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
	receiverCCVInfo protocol.CCVAddressInfo,
) (
	orderedCCVData [][]byte,
	orderedCCVOfframps []protocol.UnknownAddress,
	latestCCVTimestamp int64,
	err error,
) {
	// Map the destination verifier addresses to the CCV data associated with them.
	// This is to facilitate fast lookups in the selection below.
	destVerifierToCCVData := make(map[string]protocol.VerifierResult, len(ccvDatas))
	for _, ccvData := range ccvDatas {
		destVerifierToCCVData[ccvData.VerifierDestAddress.String()] = ccvData
	}

	selected := protocol.SelectCCVsForExecution(destVerifierToCCVData, receiverCCVInfo)

	if selected.MissingRequired != nil {
		// required CCV not found, can't execute.
		return nil, nil, 0, errors.Join(
			executor.ErrInsufficientVerifiers,
			fmt.Errorf("required CCV (%s) not found from ccv data retrieved (%+v), required: %+v",
				selected.MissingRequired.String(),
				slices.Collect(maps.Keys(destVerifierToCCVData)),
				toStrSlice(receiverCCVInfo.RequiredCCVs),
			),
		)
	}
	if !selected.Complete {
		return nil, nil, 0, errors.Join(
			executor.ErrInsufficientVerifiers,
			fmt.Errorf(
				"not enough optional CCVs found (%d) from ccv data retrieved (%+v) (required threshold: %d, optional ccvs: %+v)",
				len(selected.Optional),
				slices.Collect(maps.Keys(destVerifierToCCVData)),
				receiverCCVInfo.OptionalThreshold,
				toStrSlice(receiverCCVInfo.OptionalCCVs),
			),
		)
	}

	orderedCCVData = make([][]byte, 0, len(selected.Required)+len(selected.Optional))
	orderedCCVOfframps = make([]protocol.UnknownAddress, 0, len(selected.Required)+len(selected.Optional))

	var lastRequiredCCVTimestamp int64
	for _, result := range selected.Required {
		orderedCCVData = append(orderedCCVData, result.CCVData)
		orderedCCVOfframps = append(orderedCCVOfframps, result.VerifierDestAddress)
		lastRequiredCCVTimestamp = max(lastRequiredCCVTimestamp, result.Timestamp.UnixMilli())
	}

	optionalCCVTimestamps := make([]int64, 0, len(selected.Optional))
	for _, result := range selected.Optional {
		orderedCCVData = append(orderedCCVData, result.CCVData)
		orderedCCVOfframps = append(orderedCCVOfframps, result.VerifierDestAddress)
		optionalCCVTimestamps = append(optionalCCVTimestamps, result.Timestamp.UnixMilli())
	}

	// metrics: determine the latest timestamp of all the CCV datas.
	if receiverCCVInfo.OptionalThreshold > 0 {
		slices.Sort(optionalCCVTimestamps)
		maxSignificantOptionalCCVTimestamp := optionalCCVTimestamps[receiverCCVInfo.OptionalThreshold-1]
		latestCCVTimestamp = max(lastRequiredCCVTimestamp, maxSignificantOptionalCCVTimestamp)
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
	if cle.curseChecker == nil {
		return fmt.Errorf("curse checker is required")
	}
	if cle.verifierResultsReader == nil {
		return fmt.Errorf("verifier results reader is required")
	}
	if cle.monitoring == nil {
		return fmt.Errorf("monitoring is required")
	}
	if cle.defaultExecutorAddress == nil {
		return fmt.Errorf("default executor address map is required")
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
