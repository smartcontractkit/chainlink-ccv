package executionchecker

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
)

// IsHonestCallData reports whether the attempt passes the OffRamp CCV quorum selection with known CCV data,
// and contains no CCV entry that the selection does not use.
func IsHonestCallData(message protocol.Message, attempt protocol.ExecutionAttempt, verifierResults []protocol.VerifierResult, ccvAddressInfo protocol.CCVAddressInfo) (bool, error) {
	err := assertMessageIDsMatch(message, attempt)
	if err != nil {
		return false, err
	}

	ccvs := attempt.Report.CCVS
	if len(ccvs) != len(attempt.Report.CCVData) {
		return false, nil
	}

	resultsByCCV := make(map[string][]protocol.VerifierResult, len(verifierResults))
	for _, result := range verifierResults {
		key := result.VerifierDestAddress.String()
		resultsByCCV[key] = append(resultsByCCV[key], result)
	}

	// selectEntry mirrors the OffRamp: it selects the first submitted entry for the CCV.
	usedEntries := make(map[int]struct{}, len(ccvs))
	selectEntry := func(ccv protocol.UnknownAddress) (found, known bool) {
		index := slices.IndexFunc(ccvs, func(c protocol.UnknownAddress) bool { return c.String() == ccv.String() })
		if index == -1 {
			return false, false
		}
		usedEntries[index] = struct{}{}
		return true, slices.ContainsFunc(resultsByCCV[ccv.String()], func(result protocol.VerifierResult) bool {
			return bytes.Equal(result.CCVData, attempt.Report.CCVData[index])
		})
	}

	for _, ccv := range ccvAddressInfo.RequiredCCVs {
		if found, known := selectEntry(ccv); !found || !known {
			return false, nil
		}
	}

	remaining := int(ccvAddressInfo.OptionalThreshold)
	for _, ccv := range ccvAddressInfo.OptionalCCVs {
		if remaining == 0 {
			break
		}
		found, known := selectEntry(ccv)
		if !found {
			continue
		}
		if !known {
			return false, nil
		}
		remaining--
	}

	// The OffRamp reverts if it selects more entries than were submitted.
	return remaining == 0 && len(usedEntries) == len(ccvs), nil
}

// receiverErrorSelector is the OffRamp error that wraps every receiver revert.
var receiverErrorSelector = func() []byte {
	id := evmtypes.MustGetABI(offramp.OffRampABI).Errors["ReceiverError"].ID
	return id[:4]
}()

// IsHonestGasLimit reports whether the attempt could come from the executor, based on the gas it used.
// The executor sends no gasLimitOverride (see contracttransmitter.DefaultGasLimitOverride), so a nonzero value is not honest.
// A failed attempt is honest only if the receiver ran: the OffRamp calls token pools and CCVs with the gas that is left.
func IsHonestGasLimit(_ protocol.Message, attempt protocol.ExecutionAttempt) bool {
	if attempt.GasLimitOverride != nil && attempt.GasLimitOverride.Sign() != 0 {
		return false
	}
	if attempt.HasNonCanonicalGasEnvelope {
		return false
	}

	return !attempt.Failed || bytes.HasPrefix(attempt.FailureData, receiverErrorSelector)
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
