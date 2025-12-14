package executionchecker

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"slices"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

// ExecutionCheckerService validates execution attempts to determine if a message
// should be executed. It checks that existing attempts use honest call data and
// gas limits before allowing new execution attempts.
type ExecutionCheckerService struct {
	services.StateMachine
	destinationReaders map[protocol.ChainSelector]executor.DestinationReader
	lggr               logger.Logger
}

// Start starts the service. It implements the services.Service interface.
func (e *ExecutionCheckerService) Start(ctx context.Context) error {
	return e.StartOnce("executionchecker.Service", func() error {
		return nil
	})
}

// HasHonestAttempt reports whether an honest execution attempt has been
// made for the given message. It returns true if an honest execution attempt
// already exists, false otherwise.
func (e *ExecutionCheckerService) HasHonestAttempt(ctx context.Context, message protocol.Message, verifierResults []protocol.VerifierResult, ccvAddressInfo executor.CCVAddressInfo) (bool, error) {
	executionAttempts, err := e.destinationReaders[message.DestChainSelector].GetExecutionAttempts(ctx, message)
	if err != nil {
		return false, err
	}

	for _, attempt := range executionAttempts {
		honestCallData, err := e.isHonestCallData(message, attempt, verifierResults, ccvAddressInfo)
		honestGasLimit := e.isHonestGasLimit(message, attempt)
		if err != nil {
			continue
		}

		if honestCallData && honestGasLimit {
			return true, nil
		}
	}

	return false, nil
}

// isHonestCallData reports whether the execution attempt's call data matches
// the verifier results for all required CCVs and meets the optional CCV threshold.
func (e *ExecutionCheckerService) isHonestCallData(message protocol.Message, attempt executor.ExecutionAttempt, verifierResults []protocol.VerifierResult, ccvAddressInfo executor.CCVAddressInfo) (bool, error) {
	err := assertMessageIDsMatch(message, attempt)
	if err != nil {
		return false, err
	}

	ccvToKnownResults := mapResultsToCCVs(verifierResults)
	attemptCCVs := unknownAddressArrayToStrings(attempt.Report.CCVS)
	requiredCCVs := unknownAddressArrayToStrings(ccvAddressInfo.RequiredCCVs)
	optionalCCVs := unknownAddressArrayToStrings(ccvAddressInfo.OptionalCCVs)

	validRequiredCCVs := honestCCVs(attempt, attemptCCVs, requiredCCVs, len(requiredCCVs), ccvToKnownResults)
	validOptionalCCVs := honestCCVs(attempt, attemptCCVs, optionalCCVs, int(ccvAddressInfo.OptionalThreshold), ccvToKnownResults)

	return validRequiredCCVs && validOptionalCCVs, nil
}

// isHonestGasLimit reports whether the execution attempt's gas limit is at least
// the message's execution gas limit.
func (e *ExecutionCheckerService) isHonestGasLimit(message protocol.Message, attempt executor.ExecutionAttempt) bool {
	messageGasLimit := big.NewInt(int64(message.ExecutionGasLimit))
	return messageGasLimit.Cmp(attempt.TransactionGasLimit) <= 0
}

// honestCCVs reports whether at least threshold CCVs in messageCCVs have matching
// call data in the execution attempt when compared against known verifier results.
func honestCCVs(attempt executor.ExecutionAttempt, attemptCCVs, messageCCVs []string, threshold int, ccvToKnownResults map[string][]protocol.VerifierResult) bool {
	validCCVs := 0

	for _, ccv := range messageCCVs {
		ccvIndex := slices.Index(attemptCCVs, ccv)
		if ccvIndex == -1 || ccvIndex >= len(attempt.Report.CCVData) {
			continue
		}

		ccvData := attempt.Report.CCVData[ccvIndex]
		ccvResults := ccvToKnownResults[ccv]

		hasValidCallData := slices.ContainsFunc(ccvResults, func(result protocol.VerifierResult) bool {
			return bytes.Equal(result.CCVData, ccvData)
		})

		if hasValidCallData {
			validCCVs++

			// if we've already met the threshold, no need to check more CCVs
			if validCCVs >= threshold {
				return true
			}
		}
	}

	return validCCVs >= threshold
}

// mapResultsToCCVs groups verifier results by CCV destination address.
func mapResultsToCCVs(verifierResults []protocol.VerifierResult) map[string][]protocol.VerifierResult {
	resultsMap := make(map[string][]protocol.VerifierResult)

	for _, result := range verifierResults {
		key := result.VerifierDestAddress.String()
		resultsMap[key] = append(resultsMap[key], result)
	}

	return resultsMap
}

// assertMessageIDsMatch verifies that the message and execution attempt refer
// to the same message by comparing their message IDs.
func assertMessageIDsMatch(message protocol.Message, attempt executor.ExecutionAttempt) error {
	msgId, err := message.MessageID()
	if err != nil {
		return errors.New("unable to construct msgid from message")
	}

	attemptMsgId, err := attempt.Report.Message.MessageID()
	if err != nil {
		return errors.New("unable to construct attempt msgid")
	}

	if msgId.String() != attemptMsgId.String() {
		return errors.New("message ids do not match, attempt is not valid")
	}

	return nil
}

// unknownAddressArrayToStrings converts an array of UnknownAddress values to
// their string representations.
func unknownAddressArrayToStrings(addressArray []protocol.UnknownAddress) []string {
	result := make([]string, 0, len(addressArray))
	for _, address := range addressArray {
		result = append(result, address.String())
	}
	return result
}
