package executor

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
)

type ChainlinkExecutor struct {
	lggr                 logger.Logger
	contractTransmitters ContractTransmitter
	destinationReaders   DestinationReader
}

func NewChainlinkExecutor(
	contractTransmitters ContractTransmitter,
	destinationReaders DestinationReader,
) *ChainlinkExecutor {
	return &ChainlinkExecutor{
		contractTransmitters: contractTransmitters,
		destinationReaders:   destinationReaders,
	}
}

func (cle *ChainlinkExecutor) Validate() error {
	chainSetA := make(map[ccipocr3.ChainSelector]struct{})
	chainSetB := make(map[ccipocr3.ChainSelector]struct{})
	for _, chainID := range cle.contractTransmitters.SupportedChains() {
		chainSetA[chainID] = struct{}{}
	}

	for _, chainID := range cle.destinationReaders.SupportedChains() {
		chainSetB[chainID] = struct{}{}
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

func (cle *ChainlinkExecutor) ExecuteMessage(ctx context.Context, messageWithCCVData MessageWithCCVData) error {
	messageExecuted, err := cle.destinationReaders.IsMessageExecuted(
		ctx,
		messageWithCCVData.Message.Header.DestChainSelector,
		messageWithCCVData.Message.Header.SourceChainSelector,
		messageWithCCVData.Message.Header.SequenceNumber,
	)
	if err != nil {
		return fmt.Errorf("failed to check if message is executed: %w", err)
	}
	if messageExecuted {
		cle.lggr.Infof("message %d already executed on chain %d", messageWithCCVData.Message.Header.SequenceNumber, messageWithCCVData.Message.Header.DestChainSelector)
		return nil
	}

	ccvInfo, err := cle.destinationReaders.GetCCVSForMessage(
		ctx,
		messageWithCCVData.Message.Header.DestChainSelector,
		messageWithCCVData.Message.Header.SourceChainSelector,
		messageWithCCVData.Message.Receiver,
	)
	if err != nil {
		return fmt.Errorf("failed to get CCV Offramp addresses for message: %w", err)
	}

	ordered_ccv_offramps, ordered_ccv_data, err := cle.orderCcvData(messageWithCCVData.CCVData, ccvInfo)
	if err != nil {
		return fmt.Errorf("failed to order CCV Offramp data: %w", err)
	}

	err = cle.contractTransmitters.ConvertAndWriteMessageToChain(ctx, AbstractAggregatedReport{
		Message: messageWithCCVData.Message,
		CCVS:    ordered_ccv_offramps,
		Proofs:  ordered_ccv_data,
	})
	if err != nil {
		return fmt.Errorf("failed to transmit message to chain: %w", err)
	}

	return nil
}

func (cle *ChainlinkExecutor) orderCcvData(ccvDatum []CCVData, receiver_defined_ccvs CcvAddressInfo) ([]UnknownAddress, [][]byte, error) {
	orderedCcvData := make([][]byte, 0)
	orderedCcvOfframps := make([]UnknownAddress, 0)

	mappedCcvData := make(map[UnknownAddress][]byte)
	for _, ccvData := range ccvDatum {
		mappedCcvData[ccvData.DestVerifierAddress] = ccvData.CCVData
	}

	for _, ccvAddress := range receiver_defined_ccvs.requiredCcvs {
		if _, ok := mappedCcvData[ccvAddress]; !ok {
			return nil, nil, fmt.Errorf("required CCV Offramp %s did not have an attestation", ccvAddress)
		}
		orderedCcvData = append(orderedCcvData, mappedCcvData[ccvAddress])
		orderedCcvOfframps = append(orderedCcvOfframps, ccvAddress)
	}

	hits := 0
	for _, ccvAddress := range receiver_defined_ccvs.optionalCcvs {
		if data, ok := mappedCcvData[ccvAddress]; ok {
			orderedCcvData = append(orderedCcvData, data)
			orderedCcvOfframps = append(orderedCcvOfframps, ccvAddress)
			hits++
		}
	}
	if hits < int(receiver_defined_ccvs.optionalThreshold) {
		return nil, nil, fmt.Errorf("optional CCV Offramps did not meet threshold")
	}
	return orderedCcvOfframps, orderedCcvData, nil

}
