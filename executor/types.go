package executor

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

var (
	ErrInsufficientVerifiers = fmt.Errorf("insufficient verifiers for message")
	NtpServer                = "time.google.com"
)

// ContractAddresses is a map of contract names across all chain selectors and their address.
// Currently only one contract per chain per name is supported.
type ContractAddresses map[string]map[uint64]string

// MessageWithCCVData is a struct that represents the data in between the indexer and executor.
type MessageWithCCVData struct {
	CCVData           []protocol.VerifierResult
	Message           protocol.Message
	VerifiedTimestamp int64
}

type MessageExecutionState uint8

// Sourced from the solidity contract.
// Reference here if changes are needed.
// https://github.com/smartcontractkit/chainlink-ccip/blob/develop/chains/evm/contracts/libraries/Internal.sol#L148.
const (
	UNTOUCHED MessageExecutionState = iota
	IN_PROGRESS
	SUCCESS
	FAILURE
)

// MessageStatusResults is the translation of onchain execution state to executor's business logic behavior.
// NonEVMs which have different contracts and onchain behavior will need special handling.
type MessageStatusResults struct {
	ShouldRetry   bool
	ShouldExecute bool
}
