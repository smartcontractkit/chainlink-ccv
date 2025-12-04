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
	lggr.Infow("new chainlink executor",
		"defaultExecutorAddress", defaultExecutorAddress,
	)
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

// HandleMessage will process a single message through the executors and its components.
// 1. Check curse using the curse checker.
// 2. Check executability using the destination reader. Executability checks on chain execution state.
// 3. Get additional data (verifier results and quorum)
// 4. Confirm the additional data is sufficient for execution.
// 5. Order the CCV data to match the order expected by the receiver contract.
// 6. Create the aggregated report and transmit it to the chain.
func (cle *ChainlinkExecutor) HandleMessage(ctx context.Context, message protocol.Message) (shouldRetry bool, err error) {
	destinationChain := message.DestChainSelector
	messageID := message.MustMessageID()

	cursed := cle.curseChecker.IsRemoteChainCursed(ctx, message.DestChainSelector, message.SourceChainSelector)
	if cursed {
		cle.lggr.Infow("delaying execution due to curse", "messageID", messageID, "cursed", cursed)
		return true, nil
	}

	executability, err := cle.destinationReaders[destinationChain].GetMessageExecutability(
		ctx,
		message,
	)
	if err != nil {
		// If we can't get execution state, don't execute, but put back in heap to retry later.
		// this usually only happens due to rpc issues, other nodes will try and this node will expec to see status SUCCESS later.
		cle.lggr.Warnw("delaying execution due to failed check GetMessageExecutionState", "messageID", messageID)
		return true, err
	}
	if !executability {
		// Message is not executable due to its verification state.
		cle.lggr.Infow("skipping execution due to verification state", "messageID", messageID)
		return false, nil
	}

	verifierResults, verifierQuorum, err := cle.getVerifierResultsAndQuorum(ctx, message, messageID)
	if err != nil {
		cle.lggr.Warnw("delaying execution due to failed request for verifier results and quorum", "messageID", messageID)
		return true, err
	}
	if len(verifierResults) == 0 {
		return true, fmt.Errorf("delaying execution due to no verifier results %s", messageID.String())
	}

	// Order the Verifier Results to match the order expected by the receiver contract.
	cle.lggr.Infow("got ccv info and verifier results",
		"messageID", messageID,
		"destinationChain", destinationChain,
		"verifierQuorum", verifierQuorum,
		"verifierResultsLen", len(verifierResults),
		"verifierResultsDestVerifiers", ccvDataDestVerifiers(verifierResults),
		"verifierResultsSourceVerifiers", ccvDataSourceVerifiers(verifierResults),
	)

	// if a receiver expects more CCVs than the source message defined, we will enver be able to execute.
	// we've validated that VerifierResults are consistent in their ccv address fields, so we only need to check the first result for this check.
	if len(verifierQuorum.RequiredCCVs)+int(verifierQuorum.OptionalThreshold) > len(verifierResults[0].MessageCCVAddresses) {
		cle.lggr.Infow("skipping execution and not retrying due to impossible receiver verifier quorum", "messageID", messageID)
		return false, nil
	}

	orderedverifierResults, orderedCCVOfframps, latestCCVTimestamp, err := orderCCVData(verifierResults, verifierQuorum)
	if err != nil {
		cle.lggr.Warnw("message did not meet verifier quorum, will retry", "messageID", messageID)
		return true, err
	}

	// Create the aggregated report and transmit it to the chain.
	aggregatedReport := executor.AbstractAggregatedReport{
		CCVS:    orderedCCVOfframps,
		CCVData: orderedverifierResults,
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
		cle.lggr.Warnw("will retry execution due to failed ConvertAndWriteMessageToChain", "messageID", messageID)
		return true, err
	}

	// Record the message execution latency.
	cle.monitoring.Metrics().RecordMessageExecutionLatency(ctx, time.Since(time.Unix(latestCCVTimestamp, 0)))

	return false, nil
}

func (cle *ChainlinkExecutor) getVerifierResultsAndQuorum(ctx context.Context, message protocol.Message, messageID protocol.Bytes32) ([]protocol.VerifierResult, executor.CCVAddressInfo, error) {
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
