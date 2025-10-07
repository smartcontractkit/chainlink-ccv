package executor

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/common"
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
	monitoring            common.ExecutorMonitoring
}

func NewChainlinkExecutor(
	lggr logger.Logger,
	contractTransmitters map[protocol.ChainSelector]executor.ContractTransmitter,
	destinationReaders map[protocol.ChainSelector]executor.DestinationReader,
	verifierResultReader executor.VerifierResultReader,
	monitoring common.ExecutorMonitoring,
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
	destinationChain := message.DestChainSelector

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		messageExecuted, err := cle.destinationReaders[destinationChain].IsMessageExecuted(
			ctx,
			message,
		)
		if err != nil {
			return fmt.Errorf("failed to check IsMessageExecuted: %w", err)
		}
		if messageExecuted {
			cle.lggr.Infof("message %d already executed on chain %d, skipping...", message.Nonce, destinationChain)
			return executor.ErrMsgAlreadyExecuted
		}
		return nil
	})

	ccvData := make([]protocol.CCVData, 0)
	g.Go(func() error {
		id, _ := message.MessageID()
		res, err := cle.verifierResultsReader.GetVerifierResults(ctx, id)
		if err != nil {
			return fmt.Errorf("failed to get CCV data for message: %w", err)
		}
		ccvData = append(ccvData, res...)
		return nil
	})

	var ccvInfo executor.CcvAddressInfo
	g.Go(func() error {
		res, err := cle.destinationReaders[destinationChain].GetCCVSForMessage(
			ctx,
			message,
		)
		if err != nil && len(ccvInfo.RequiredCcvs) == 0 {
			return fmt.Errorf("failed to get CCV Offramp info for message: %w", err)
		}
		ccvInfo = res
		return nil
	})

	if err := g.Wait(); err != nil {
		return err
	}

	aggregatedReport, CCVTimestamp, err := cle.orderCcvData(message, ccvData, ccvInfo)
	if err != nil {
		return fmt.Errorf("failed to order CCV Offramp data: %w", err)
	}

	err = cle.contractTransmitters[destinationChain].ConvertAndWriteMessageToChain(ctx, aggregatedReport)
	if err != nil {
		return fmt.Errorf("failed to transmit message to chain: %w", err)
	}
	duration := time.Since(time.Unix(CCVTimestamp, 0))
	cle.lggr.Infof("CVVTimestamp: %d, duration: %ds", CCVTimestamp, int(duration.Seconds()))
	cle.monitoring.Metrics().RecordMessageExecutionLatency(ctx, duration)

	return nil
}

func (cle *ChainlinkExecutor) orderCcvData(message protocol.Message, ccvData []protocol.CCVData, receiverDefinedCcvs executor.CcvAddressInfo) (executor.AbstractAggregatedReport, int64, error) {
	orderedCcvData := make([][]byte, 0)
	orderedCcvOfframps := make([]protocol.UnknownAddress, 0)

	mappedCcvData := make(map[string]protocol.CCVData)
	for _, datum := range ccvData {
		mappedCcvData[strings.ToLower(datum.DestVerifierAddress.String())] = datum
	}

	var lastRequiredCCVTimestamp int64
	for _, ccvAddress := range receiverDefinedCcvs.RequiredCcvs {
		strAddr := strings.ToLower(string(ccvAddress))
		if _, ok := mappedCcvData[strAddr]; !ok {
			return executor.AbstractAggregatedReport{}, 0, executor.ErrInsufficientVerifiers
		}
		orderedCcvData = append(orderedCcvData, mappedCcvData[strAddr].CCVData)
		orderedCcvOfframps = append(orderedCcvOfframps, ccvAddress)
		lastRequiredCCVTimestamp = max(lastRequiredCCVTimestamp, mappedCcvData[strAddr].Timestamp)
	}

	optionalCCVTimestamps := make([]int64, 0, len(receiverDefinedCcvs.OptionalCcvs))
	for _, ccvAddress := range receiverDefinedCcvs.OptionalCcvs {
		if data, ok := mappedCcvData[ccvAddress.String()]; ok {
			orderedCcvData = append(orderedCcvData, data.CCVData)
			orderedCcvOfframps = append(orderedCcvOfframps, ccvAddress)
			optionalCCVTimestamps = append(optionalCCVTimestamps, data.Timestamp)
		}
	}

	// check if we have enough optional CCVs. If any required CCVs were missing
	// we would have already returned error above
	if len(orderedCcvData)-len(receiverDefinedCcvs.RequiredCcvs) < int(receiverDefinedCcvs.OptionalThreshold) {
		return executor.AbstractAggregatedReport{}, 0, executor.ErrInsufficientVerifiers
	}
	var CCVTimestamp int64
	if receiverDefinedCcvs.OptionalThreshold > 0 {
		slices.Sort(optionalCCVTimestamps)
		minSignificantOptionalCCVTimestamp := optionalCCVTimestamps[receiverDefinedCcvs.OptionalThreshold-1]
		CCVTimestamp = max(lastRequiredCCVTimestamp, minSignificantOptionalCCVTimestamp)
	} else {
		CCVTimestamp = lastRequiredCCVTimestamp
	}

	return executor.AbstractAggregatedReport{
		Message: message,
		CCVS:    orderedCcvOfframps,
		CCVData: orderedCcvData,
	}, CCVTimestamp, nil
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
