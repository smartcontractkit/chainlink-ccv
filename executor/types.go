package executor

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

var (
	ErrMsgAlreadyExecuted    = fmt.Errorf("message already executed")
	ErrInsufficientVerifiers = fmt.Errorf("insufficient verifiers for message")
)

type AbstractAggregatedReport struct {
	CCVS    []protocol.UnknownAddress
	CCVData [][]byte
	Message protocol.Message
}

// ContractAddresses is a map of contract names across all chain selectors and their address.
// Currently only one contract per chain per name is supported.
type ContractAddresses map[string]map[uint64]string

// MessageWithCCVData is a struct that represents the data in between the indexer and executor.
type MessageWithCCVData struct {
	CCVData           []protocol.CCVData
	Message           protocol.Message
	VerifiedTimestamp int64
}

type CcvAddressInfo struct {
	RequiredCcvs      []protocol.UnknownAddress
	OptionalCcvs      []protocol.UnknownAddress
	OptionalThreshold uint8
}
