package executionchecker

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// IsHonestCallData reports whether the execution attempt's call data matches
// the verifier results for all required CCVs and meets the optional CCV threshold.
func IsHonestCallData(message protocol.Message, attempt protocol.ExecutionAttempt, verifierResults []protocol.VerifierResult, ccvAddressInfo protocol.CCVAddressInfo) (bool, error) {
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

// IsHonestGasLimit reports whether the execution attempt's gas limit is at least
// the message's execution gas limit.
func IsHonestGasLimit(message protocol.Message, attempt protocol.ExecutionAttempt) bool {
	messageGasLimit := big.NewInt(int64(message.ExecutionGasLimit))
	return messageGasLimit.Cmp(attempt.TransactionGasLimit) <= 0
}

// honestCCVs reports whether at least threshold CCVs in expectedCCVs have matching
// call data in the execution attempt when compared against known verifier results.
func honestCCVs(attempt protocol.ExecutionAttempt, attemptCCVs, expectedCCVs []string, threshold int, expectedCCVsToKnownResults map[string][]protocol.VerifierResult) bool {
	validCCVs := 0

	for _, ccv := range expectedCCVs {
		ccvIndex := slices.Index(attemptCCVs, ccv)
		if ccvIndex == -1 || ccvIndex >= len(attempt.Report.CCVData) {
			continue
		}

		ccvData := attempt.Report.CCVData[ccvIndex]
		ccvResults := expectedCCVsToKnownResults[ccv]

		hasValidCCVData := slices.ContainsFunc(ccvResults, func(result protocol.VerifierResult) bool {
			return bytes.Equal(result.CCVData, ccvData)
		})

		if hasValidCCVData {
			validCCVs++

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
func assertMessageIDsMatch(message protocol.Message, attempt protocol.ExecutionAttempt) error {
	msgID, err := message.MessageID()
	if err != nil {
		return errors.New("unable to construct msgid from message")
	}

	attemptMsgID, err := attempt.Report.Message.MessageID()
	if err != nil {
		return errors.New("unable to construct attempt msgid")
	}

	if msgID.String() != attemptMsgID.String() {
		return fmt.Errorf("message ids do not match, attempt is not valid, expected: %s, got: %s", msgID.String(), attemptMsgID.String())
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
