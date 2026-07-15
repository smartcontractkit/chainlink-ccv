package executor

import (
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

const DefaultDataNotReadyRetryInterval = 1 * time.Second

var (
	ErrInsufficientVerifiers = fmt.Errorf("insufficient verifiers for message")
	ErrMessageEncoding       = fmt.Errorf("message encoding failed")
	ErrExecutionContended    = fmt.Errorf("execution attempted; retry must respect executor stagger")
	NtpServer                = "time.google.com"
)

// BroadcastErrorCause is the `cause` metric label for a failed transmit attempt.
// It is a closed set; add a new cause here when the executor learns to classify one.
type BroadcastErrorCause string

const (
	BroadcastCauseInsufficientFunds BroadcastErrorCause = "insufficient_funds"
)

// BroadcastError is returned by a transmitter when an execute attempt fails in a way the
// executor classifies for metrics. It carries the cause and the sending address (captured
// at the point of failure), so the executor can classify without string-matching.
type BroadcastError struct {
	Cause       BroadcastErrorCause
	FromAddress string // may be empty when no single sender applies
	Err         error
}

func (e *BroadcastError) Error() string {
	return fmt.Sprintf("broadcast attempt failed (%s): %v", e.Cause, e.Err)
}

func (e *BroadcastError) Unwrap() error { return e.Err }

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
