package types

import (
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

type AbstractAggregatedReport struct {
	CCVS    []types.UnknownAddress
	CCVData [][]byte
	Message types.Message
}

// ContractAddresses is a map of contract names across all chain selectors and their address.
// Currently only one contract per chain per name is supported.
type ContractAddresses map[string]map[uint64]string

// MessageWithCCVData is a struct that represents the data in between the indexer and executor.
type MessageWithCCVData struct {
	CCVData        []types.CCVData
	Message        types.Message
	ReadyTimestamp int64
}

type CcvAddressInfo struct {
	RequiredCcvs      []types.UnknownAddress
	OptionalCcvs      []types.UnknownAddress
	OptionalThreshold uint8
}
