package executor

import (
	"context"
	"fmt"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	ct "github.com/smartcontractkit/chainlink-ccv/executor/pkg/contracttransmitter"
	dr "github.com/smartcontractkit/chainlink-ccv/executor/pkg/destinationreader"
)

// Ensure ChainlinkExecutor implements the Executor interface.
var _ executor.Executor = &ChainlinkExecutor{}

type ChainlinkExecutor struct {
	lggr                 logger.Logger
	contractTransmitters map[protocol.ChainSelector]ct.ContractTransmitter
	destinationReaders   map[protocol.ChainSelector]dr.DestinationReader
}

func NewChainlinkExecutor(
	lggr logger.Logger,
	contractTransmitters map[protocol.ChainSelector]ct.ContractTransmitter,
	destinationReaders map[protocol.ChainSelector]dr.DestinationReader,
) *ChainlinkExecutor {
	return &ChainlinkExecutor{
		lggr:                 lggr,
		contractTransmitters: contractTransmitters,
		destinationReaders:   destinationReaders,
	}
}

func (cle *ChainlinkExecutor) CheckValidMessage(ctx context.Context, messageWithCCVData types.MessageWithCCVData) error {
	destinationChain := messageWithCCVData.Message.DestChainSelector
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

func (cle *ChainlinkExecutor) ExecuteMessage(ctx context.Context, messageWithCCVData types.MessageWithCCVData) error {
	destinationChain := messageWithCCVData.Message.DestChainSelector
	messageExecuted, err := cle.destinationReaders[destinationChain].IsMessageExecuted(
		ctx,
		messageWithCCVData.Message,
	)
	if err != nil {
		return fmt.Errorf("failed to check if message is executed: %w", err)
	}
	if messageExecuted {
		cle.lggr.Infof("message %d already executed on chain %d", messageWithCCVData.Message.Nonce, messageWithCCVData.Message.DestChainSelector)
		return nil
	}

	ccvInfo, err := cle.destinationReaders[destinationChain].GetCCVSForMessage(
		ctx,
		messageWithCCVData.Message,
	)
	if err != nil && len(ccvInfo.RequiredCcvs) == 0 {
		return fmt.Errorf("failed to get CCV Offramp info for message: %w", err)
	}

	orderedCcvOfframps, orderedCcvData, err := cle.orderCcvData(messageWithCCVData.CCVData, ccvInfo)
	if err != nil {
		return fmt.Errorf("failed to order CCV Offramp data: %w", err)
	}

	err = cle.contractTransmitters[destinationChain].ConvertAndWriteMessageToChain(ctx, types.AbstractAggregatedReport{
		Message: messageWithCCVData.Message,
		CCVS:    orderedCcvOfframps,
		CCVData: orderedCcvData,
	})
	if err != nil {
		return fmt.Errorf("failed to transmit message to chain: %w", err)
	}

	return nil
}

func (cle *ChainlinkExecutor) orderCcvData(ccvData []protocol.CCVData, receiverDefinedCcvs types.CcvAddressInfo) ([]protocol.UnknownAddress, [][]byte, error) {
	orderedCcvData := make([][]byte, 0)
	orderedCcvOfframps := make([]protocol.UnknownAddress, 0)

	mappedCcvData := make(map[string][]byte)
	for _, datum := range ccvData {
		mappedCcvData[strings.ToLower(datum.DestVerifierAddress.String())] = datum.CCVData
	}

	for _, ccvAddress := range receiverDefinedCcvs.RequiredCcvs {
		strAddr := strings.ToLower(string(ccvAddress))
		if _, ok := mappedCcvData[strAddr]; !ok {
			return nil, nil, fmt.Errorf("required CCV Offramp %s did not have an attestation", strAddr)
		}
		orderedCcvData = append(orderedCcvData, mappedCcvData[strAddr])
		orderedCcvOfframps = append(orderedCcvOfframps, ccvAddress)
	}

	for _, ccvAddress := range receiverDefinedCcvs.OptionalCcvs {
		if data, ok := mappedCcvData[ccvAddress.String()]; ok {
			orderedCcvData = append(orderedCcvData, data)
			orderedCcvOfframps = append(orderedCcvOfframps, ccvAddress)
		}
	}

	// check if we have enough optional CCVs. If any required CCVs were missing
	// we would have already returned error above
	if len(orderedCcvData)-len(receiverDefinedCcvs.RequiredCcvs) < int(receiverDefinedCcvs.OptionalThreshold) {
		return nil, nil, fmt.Errorf("optional CCV Offramps did not meet threshold")
	}
	return orderedCcvOfframps, orderedCcvData, nil
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
