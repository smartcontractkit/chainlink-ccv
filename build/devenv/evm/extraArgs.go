package evm

import "github.com/smartcontractkit/chainlink-ccv/protocol"

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

// TODO: import these from Solana family.
type SVMMessageOptions struct {
	Version                  uint8
	ComputeUnits             uint32
	AccountIsWritableBitmap  uint64
	AllowOutOfOrderExecution bool
	TokenReceiver            [32]byte
	Accounts                 [][32]byte
}

func (m SVMMessageOptions) IsExtraArgsDataProvider() {}
