package cciptestinterfaces

import "github.com/smartcontractkit/chainlink-ccv/protocol"

// ExtraArgsOption mutates a chain-specific ExtraArgsDataProvider that has been
// allocated by a destination chain's ExtraArgsBuilder. Each chain family defines
// its own option constructors (e.g. evm.WithExecutionGasLimit) that type-assert
// the provider to the concrete struct; applying an option to the wrong chain
// family returns an error rather than silently no-op'ing.
type ExtraArgsOption func(ExtraArgsDataProvider) error

// MessageOptions consists of all the ways one can modify a CCIP message
// using extraArgs.
type MessageOptions struct {
	// Version indicates the version of the extraArgs.
	Version uint8
	// ExecutionGasLimit is the execution gas limit for the message
	ExecutionGasLimit uint32
	// OutOfOrderExecution is whether to execute the message out of order
	OutOfOrderExecution bool
	// CCVs are the CCVs for the message
	CCVs []protocol.CCV
	// FinalityConfig is the finality config for the message
	FinalityConfig protocol.Finality
	// Executor is the executor address
	Executor protocol.UnknownAddress
	// ExecutorArgs are the executor arguments for the message
	ExecutorArgs []byte
	// TokenArgs are the token arguments for the message
	TokenArgs []byte
	// UseTestRouter when true looks up the TestRouter contract type in the datastore instead of Router.
	UseTestRouter bool
}

func (m MessageOptions) IsExtraArgsDataProvider() {}

type SVMMessageOptions struct {
	Version                  uint8
	ComputeUnits             uint32
	AccountIsWritableBitmap  uint64
	AllowOutOfOrderExecution bool
	TokenReceiver            [32]byte
	Accounts                 [][32]byte
}

func (m SVMMessageOptions) IsExtraArgsDataProvider() {}
