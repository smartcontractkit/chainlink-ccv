package evm

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// mutateMessageOptions type-asserts the provider to *cciptestinterfaces.MessageOptions
// (the EVM family's destination-shaped extra args) and applies the given mutation.
// It returns an error if the provider is not the EVM variant, so a test that passes
// an EVM option to a non-EVM destination fails loudly rather than silently no-op'ing.
func mutateMessageOptions(name string, p cciptestinterfaces.ExtraArgsDataProvider, mut func(*cciptestinterfaces.MessageOptions)) error {
	m, ok := p.(*cciptestinterfaces.MessageOptions)
	if !ok {
		return fmt.Errorf("%s: expected *cciptestinterfaces.MessageOptions (EVM family), got %T", name, p)
	}
	mut(m)
	return nil
}

func WithVersion(v uint8) cciptestinterfaces.ExtraArgsOption {
	return func(p cciptestinterfaces.ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithVersion", p, func(m *cciptestinterfaces.MessageOptions) { m.Version = v })
	}
}

func WithExecutionGasLimit(limit uint32) cciptestinterfaces.ExtraArgsOption {
	return func(p cciptestinterfaces.ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithExecutionGasLimit", p, func(m *cciptestinterfaces.MessageOptions) { m.ExecutionGasLimit = limit })
	}
}

func WithOutOfOrderExecution(b bool) cciptestinterfaces.ExtraArgsOption {
	return func(p cciptestinterfaces.ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithOutOfOrderExecution", p, func(m *cciptestinterfaces.MessageOptions) { m.OutOfOrderExecution = b })
	}
}

func WithCCVs(ccvs []protocol.CCV) cciptestinterfaces.ExtraArgsOption {
	return func(p cciptestinterfaces.ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithCCVs", p, func(m *cciptestinterfaces.MessageOptions) { m.CCVs = ccvs })
	}
}

func WithFinalityConfig(fc protocol.Finality) cciptestinterfaces.ExtraArgsOption {
	return func(p cciptestinterfaces.ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithFinalityConfig", p, func(m *cciptestinterfaces.MessageOptions) { m.FinalityConfig = fc })
	}
}

func WithExecutor(addr protocol.UnknownAddress) cciptestinterfaces.ExtraArgsOption {
	return func(p cciptestinterfaces.ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithExecutor", p, func(m *cciptestinterfaces.MessageOptions) { m.Executor = addr })
	}
}

func WithExecutorArgs(args []byte) cciptestinterfaces.ExtraArgsOption {
	return func(p cciptestinterfaces.ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithExecutorArgs", p, func(m *cciptestinterfaces.MessageOptions) { m.ExecutorArgs = args })
	}
}

func WithTokenArgs(args []byte) cciptestinterfaces.ExtraArgsOption {
	return func(p cciptestinterfaces.ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithTokenArgs", p, func(m *cciptestinterfaces.MessageOptions) { m.TokenArgs = args })
	}
}

func WithUseTestRouter(b bool) cciptestinterfaces.ExtraArgsOption {
	return func(p cciptestinterfaces.ExtraArgsDataProvider) error {
		return mutateMessageOptions("evm.WithUseTestRouter", p, func(m *cciptestinterfaces.MessageOptions) { m.UseTestRouter = b })
	}
}
