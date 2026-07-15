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

// InsufficientFundsCause is the value of the `cause` metric label used when a transmit
// attempt is rejected for lack of native funds. It follows the cause-label pattern used
// by the chainlink-framework TXM attempt-error metric.
const InsufficientFundsCause = "insufficient_funds"

// InsufficientFundsError indicates a transmit attempt was rejected because the
// transmitter's sending address lacked native funds for gas. It carries the sending
// address so the metric can be labelled by fromAddress (and cause). A transmitter
// returns this so the executor can classify the failure without string-matching.
type InsufficientFundsError struct {
	// FromAddress is the transmitter's sending address that was underfunded.
	FromAddress string
	// Err is the underlying transmit error.
	Err error
}

func (e *InsufficientFundsError) Error() string {
	return fmt.Sprintf("insufficient funds on transmitter %s: %v", e.FromAddress, e.Err)
}

func (e *InsufficientFundsError) Unwrap() error { return e.Err }

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
