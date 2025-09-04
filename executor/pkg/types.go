package pkg

import (
	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
)

type AbstractAggregatedReport struct {
	Message common.Message
	CCVS    []common.UnknownAddress
	CCVData [][]byte
}

// ContractAddresses is a map of contract names across all chain selectors and their address.
// Currently only one contract per chain per name is supported.
type ContractAddresses map[string]map[uint64]string

// MessageWithCCVData is a struct that represents the data in between the indexer and executor
type MessageWithCCVData struct {
	Message        common.Message
	CCVData        []common.CCVData
	ReadyTimestamp uint64
}

type CcvAddressInfo struct {
	requiredCcvs      []common.UnknownAddress
	optionalCcvs      []common.UnknownAddress
	optionalThreshold uint8
}
