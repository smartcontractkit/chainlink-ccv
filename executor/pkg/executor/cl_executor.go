package executor

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Ensure ChainlinkExecutor implements the Executor interface.
var _ executor.Executor = &ChainlinkExecutor{}

type ChainlinkExecutor struct {
	lggr                  logger.Logger
	contractTransmitters  map[protocol.ChainSelector]executor.ContractTransmitter
	destinationReaders    map[protocol.ChainSelector]executor.DestinationReader
	verifierResultsReader executor.VerifierResultReader
	monitoring            executor.Monitoring
}

func NewChainlinkExecutor(
	lggr logger.Logger,
	contractTransmitters map[protocol.ChainSelector]executor.ContractTransmitter,
	destinationReaders map[protocol.ChainSelector]executor.DestinationReader,
	verifierResultReader executor.VerifierResultReader,
	monitoring executor.Monitoring,
) *ChainlinkExecutor {
	return &ChainlinkExecutor{
		lggr:                  lggr,
		contractTransmitters:  contractTransmitters,
		destinationReaders:    destinationReaders,
		verifierResultsReader: verifierResultReader,
		monitoring:            monitoring,
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
	messageID, err := message.MessageID()
	if err != nil {
		return fmt.Errorf("failed to get message ID: %w", err)
	}

	// Check if the message is already executed so as to not waste gas and time.
	destinationChain := message.DestChainSelector
	executed, err := cle.destinationReaders[destinationChain].IsMessageExecuted(
		ctx,
		message,
	)
	if err != nil {
		return fmt.Errorf("failed to check IsMessageExecuted: %w", err)
	}
	if executed {
		cle.lggr.Infof("message %x (nonce %d) already executed on chain %d, skipping...", messageID, message.Nonce, destinationChain)
		return executor.ErrMsgAlreadyExecuted
	}

	// Fetch CCV data from the indexer and CCV info from the destination reader
	// concurrently.
	g, ctx := errgroup.WithContext(ctx)
	ccvData := make([]protocol.CCVData, 0)
	g.Go(func() error {
		res, err := cle.verifierResultsReader.GetVerifierResults(ctx, messageID)
		if err != nil {
			return fmt.Errorf("failed to get CCV data for message %x: %w", messageID, err)
		}
		ccvData = append(ccvData, res...)
		return nil
	})

	var ccvInfo executor.CCVAddressInfo
	g.Go(func() error {
		res, err := cle.destinationReaders[destinationChain].GetCCVSForMessage(
			ctx,
			message,
		)
		if err != nil && len(ccvInfo.RequiredCCVs) == 0 {
			return fmt.Errorf("failed to get CCV Offramp info for message %x: %w", messageID, err)
		}
		ccvInfo = res
		return nil
	})

	if err := g.Wait(); err != nil {
		return err
	}

	// Order the CCV data to match the order expected by the receiver contract.
	cle.lggr.Infow("got ccv info and ccvData for message",
		"messageID", messageID,
		"destinationChain", destinationChain,
		"ccvInfo", ccvInfo,
		"ccvDatasLen", len(ccvData),
		"ccvDatasDestVerifiers", ccvDataDestVerifiers(ccvData),
		"ccvDatasSourceVerifiers", ccvDataSourceVerifiers(ccvData),
	)
	orderedCCVData, orderedCCVOfframps, latestCCVTimestamp, err := orderCCVData(ccvData, ccvInfo)
	if err != nil {
		return fmt.Errorf("failed to order CCV Offramp data for message %x: %w", messageID, err)
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
		return fmt.Errorf("failed to transmit message %x to chain %d: %w", messageID, destinationChain, err)
	}

	// Record the message execution latency.
	cle.monitoring.Metrics().RecordMessageExecutionLatency(ctx, time.Since(time.Unix(latestCCVTimestamp, 0)))

	return nil
}

func ccvDataDestVerifiers(ccvDatas []protocol.CCVData) []string {
	destVerifiers := make([]string, 0, len(ccvDatas))
	for _, ccvData := range ccvDatas {
		destVerifiers = append(destVerifiers, ccvData.DestVerifierAddress.String())
	}
	return destVerifiers
}

func ccvDataSourceVerifiers(ccvDatas []protocol.CCVData) []string {
	sourceVerifiers := make([]string, 0, len(ccvDatas))
	for _, ccvData := range ccvDatas {
		sourceVerifiers = append(sourceVerifiers, ccvData.SourceVerifierAddress.String())
	}
	return sourceVerifiers
}

// orderCCVData orders the CCV data retrieved from the indexer to match the order expected
// by the receiver contract.
func orderCCVData(
	ccvDatas []protocol.CCVData,
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
	destVerifierToCCVData := make(map[string]protocol.CCVData)
	for _, ccvData := range ccvDatas {
		destVerifierToCCVData[ccvData.DestVerifierAddress.String()] = ccvData
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
		lastRequiredCCVTimestamp = max(lastRequiredCCVTimestamp, data.Timestamp)
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
		optionalCCVTimestamps = append(optionalCCVTimestamps, data.Timestamp)
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
