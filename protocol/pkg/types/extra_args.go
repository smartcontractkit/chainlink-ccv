package types

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/hash"
)

var (
	// ExtraArgs version tags.
	EVMExtraArgsV1Tag = hash.Keccak256([]byte("CCIP EVMExtraArgsV1"))[:4]
	EVMExtraArgsV2Tag = hash.Keccak256([]byte("CCIP EVMExtraArgsV2"))[:4]
	EVMExtraArgsV3Tag = hash.Keccak256([]byte("CCIP EVMExtraArgsV3"))[:4]
)

// EVMExtraArgsV1 represents the basic extra args format.
type EVMExtraArgsV1 struct {
	GasLimit *big.Int
}

// ToBytes encodes EVMExtraArgsV1 to bytes.
func (e *EVMExtraArgsV1) ToBytes() []byte {
	if e == nil {
		return nil
	}
	data := make([]byte, 0, len(EVMExtraArgsV1Tag)+32)
	data = append(data, EVMExtraArgsV1Tag...)
	if e.GasLimit != nil {
		gasLimitBytes := make([]byte, 32)
		e.GasLimit.FillBytes(gasLimitBytes)
		data = append(data, gasLimitBytes...)
	}
	return data
}

// FromBytes decodes EVMExtraArgsV1 from bytes.
func (e *EVMExtraArgsV1) FromBytes(data []byte) error {
	if len(data) == 0 {
		e.GasLimit = big.NewInt(200_000)
		return nil
	}
	if !bytes.HasPrefix(data, EVMExtraArgsV1Tag) {
		return fmt.Errorf("invalid EVMExtraArgsV1 tag")
	}
	data = data[len(EVMExtraArgsV1Tag):]
	if len(data) < 32 {
		return fmt.Errorf("data too short")
	}
	e.GasLimit = new(big.Int).SetBytes(data[:32])
	return nil
}

// GenericExtraArgsV2 represents the v2 extra args format with out-of-order execution.
type GenericExtraArgsV2 struct {
	GasLimit                 *big.Int
	AllowOutOfOrderExecution bool
}

// ToBytes encodes GenericExtraArgsV2 to bytes.
func (e *GenericExtraArgsV2) ToBytes() []byte {
	if e == nil {
		return nil
	}
	data := make([]byte, 0, len(EVMExtraArgsV2Tag)+32+1) // tag + gasLimit + bool
	data = append(data, EVMExtraArgsV2Tag...)
	if e.GasLimit != nil {
		gasLimitBytes := make([]byte, 32)
		e.GasLimit.FillBytes(gasLimitBytes)
		data = append(data, gasLimitBytes...)
	}
	if e.AllowOutOfOrderExecution {
		data = append(data, 1)
	} else {
		data = append(data, 0)
	}
	return data
}

// FromBytes decodes GenericExtraArgsV2 from bytes.
func (e *GenericExtraArgsV2) FromBytes(data []byte) error {
	if len(data) == 0 {
		e.GasLimit = big.NewInt(200_000)
		e.AllowOutOfOrderExecution = false
		return nil
	}
	if !bytes.HasPrefix(data, EVMExtraArgsV2Tag) {
		return fmt.Errorf("invalid GenericExtraArgsV2 tag")
	}
	data = data[len(EVMExtraArgsV2Tag):]
	if len(data) < 33 { // 32 bytes for gas limit + 1 byte for bool
		return fmt.Errorf("data too short")
	}
	e.GasLimit = new(big.Int).SetBytes(data[:32])
	e.AllowOutOfOrderExecution = data[32] == 1
	return nil
}

// CCV represents a Cross-Chain Verifier configuration.
type CCV struct {
	CCVAddress UnknownAddress
	Args       []byte
	ArgsLen    uint16
}

// EVMExtraArgsV3 represents the v3 extra args format with modular security.
type EVMExtraArgsV3 struct {
	RequiredCCV       []CCV
	OptionalCCV       []CCV
	Executor          UnknownAddress
	ExecutorArgs      []byte
	TokenArgs         []byte
	FinalityConfig    uint16
	RequiredCCVLen    uint16
	OptionalCCVLen    uint16
	ExecutorArgsLen   uint16
	TokenArgsLen      uint16
	OptionalThreshold uint8
}
