package cciptestinterfaces

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// ExtraArgsOption mutates a chain-specific ExtraArgsDataProvider that has been
// allocated by a destination chain's ExtraArgsBuilder. Each chain family defines
// its own option constructors (e.g. evm.WithExecutionGasLimit) that type-assert
// the provider to the concrete struct; applying an option to the wrong chain
// family returns an error rather than silently no-op'ing.
type ExtraArgsOption func(ExtraArgsDataProvider) error

// MessageOptions represents EVM modifications one can make to a CCIP message for through extra args.
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
}

func (m MessageOptions) IsExtraArgsDataProvider() {}

// mutateMessageOptions type-asserts the provider to *MessageOptions
// (the EVM family's destination-shaped extra args) and applies the given mutation.
// It returns an error if the provider is not the EVM variant, so a test that passes
// an EVM option to a non-EVM destination fails loudly rather than silently no-op'ing.
func mutateMessageOptions(name string, p ExtraArgsDataProvider, mut func(*MessageOptions)) error {
	m, ok := p.(*MessageOptions)
	if !ok {
		return fmt.Errorf("%s: expected *MessageOptions (EVM family), got %T", name, p)
	}
	mut(m)
	return nil
}

func WithVersion(v uint8) ExtraArgsOption {
	return func(p ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithVersion", p, func(m *MessageOptions) { m.Version = v })
	}
}

func WithExecutionGasLimit(limit uint32) ExtraArgsOption {
	return func(p ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithExecutionGasLimit", p, func(m *MessageOptions) { m.ExecutionGasLimit = limit })
	}
}

func WithOutOfOrderExecution(b bool) ExtraArgsOption {
	return func(p ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithOutOfOrderExecution", p, func(m *MessageOptions) { m.OutOfOrderExecution = b })
	}
}

func WithCCVs(ccvs []protocol.CCV) ExtraArgsOption {
	return func(p ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithCCVs", p, func(m *MessageOptions) { m.CCVs = ccvs })
	}
}

func WithFinalityConfig(fc protocol.Finality) ExtraArgsOption {
	return func(p ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithFinalityConfig", p, func(m *MessageOptions) { m.FinalityConfig = fc })
	}
}

func WithExecutor(addr protocol.UnknownAddress) ExtraArgsOption {
	return func(p ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithExecutor", p, func(m *MessageOptions) { m.Executor = addr })
	}
}

func WithExecutorArgs(args []byte) ExtraArgsOption {
	return func(p ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithExecutorArgs", p, func(m *MessageOptions) { m.ExecutorArgs = args })
	}
}

func WithTokenArgs(args []byte) ExtraArgsOption {
	return func(p ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithTokenArgs", p, func(m *MessageOptions) { m.TokenArgs = args })
	}
}

type SVMMessageOptions struct {
	Version                  uint8
	ComputeUnits             uint32
	AccountIsWritableBitmap  uint64
	AllowOutOfOrderExecution bool
	TokenReceiver            [32]byte
	Accounts                 [][32]byte
}

func (m SVMMessageOptions) IsExtraArgsDataProvider() {}
