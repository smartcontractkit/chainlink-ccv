package cciptestinterfaces

import (
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// MessageOptions represents modifications one can make to a CCIP messagev3 through extra args.
// TODO: rename this to GenericExtraArgsV3.
type MessageOptions struct {
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

// This fulfills the marker interface ExtraArgsDataProvider.
func (m MessageOptions) IsExtraArgsDataProvider() {}

// MessageV3Destination is an interface for any chain that can receive a V3 message.
// We use an interface rather than a struct because the V3 message structure is chain agnostic.
type MessageV3Destination interface {
	// GetExecutorArgs returns the executor arguments for the message.
	// The opts parameter will be passed by the caller, implementer should type assert the opts to the concrete type.
	GetExecutorArgs(opts any) ([]byte, error)
	// GetTokenArgs returns the token arguments for the message.
	// The opts parameter will be passed by the caller, implementer should type assert the opts to the concrete type.
	GetTokenArgs(opts any) ([]byte, error)
}

// MessageV3Source is an interface for any chain that can send a V3 message.
// We use an interface rather than a struct because the V3 message structure is chain agnostic.
type MessageV3Source interface {
	// BuildV3ExtraArgs builds the V3 extra arguments for the message including calling the destination chain's GetExecutorArgs and GetTokenArgs.
	// then serializing the results into the source chain specific encoding format, and returning the result.
	BuildV3ExtraArgs(
		opts MessageOptions,
		destChain MessageV3Destination,
		executorArgsParams any,
		tokenArgsParams any,
	) ([]byte, error)
}

// Any2EVMMessageV2Data represents the data for V2 messages arriving at an EVM chain.
type Any2EVMMessageV2Data struct {
	GasLimit                 uint32
	AllowOutOfOrderExecution bool
}

// This fulfills the marker interface ExtraArgsDataProvider.
func (m Any2EVMMessageV2Data) IsExtraArgsDataProvider() {}

// Any2EVMMessageV2 is an interface for any chain that can send a V2 message to an EVM chain.
type Any2EVMMessageV2 interface {
	SerializeAny2EVMMessageV2(opts any) ([]byte, error)
}

// Any2EVMMessageV1Data represents the data for V1 messages arriving at an EVM chain.
type Any2EVMMessageV1Data struct {
	GasLimit uint32
}

// This fulfills the marker interface ExtraArgsDataProvider.
func (m Any2EVMMessageV1Data) IsExtraArgsDataProvider() {}

// Any2EVMMessageV1 is an interface for any chain that can send a V1 message to an EVM chain.
type Any2EVMMessageV1 interface {
	SerializeAny2EVMMessageV1(opts any) ([]byte, error)
}

// Any2SVMMessageV1Data represents the data for V1 messages arriving at a SVM chain.
type Any2SVMMessageV1Data struct {
	Version                  uint8
	ComputeUnits             uint32
	AccountIsWritableBitmap  uint64
	AllowOutOfOrderExecution bool
	TokenReceiver            [32]byte
	Accounts                 [][32]byte
}

// This fulfills the marker interface ExtraArgsDataProvider.
func (m Any2SVMMessageV1Data) IsExtraArgsDataProvider() {}

// Any2SVMMessageV1 is an interface for any chain that can send a V1 message to a SVM chain.
type Any2SVMMessageV1 interface {
	SerializeAny2SVMMessageV1(opts any) ([]byte, error)
}
