package executor

import (
	"encoding/json"
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

// MarshalJSON implements the json.Marshaler interface for AbstractAggregatedReport.
// CCVS and CCVData are marshaled as hex strings.
func (a AbstractAggregatedReport) MarshalJSON() ([]byte, error) {
	ccvData := make([]protocol.ByteSlice, len(a.CCVData))
	for i, data := range a.CCVData {
		ccvData[i] = protocol.ByteSlice(data)
	}
	return json.Marshal(struct {
		CCVS    []protocol.UnknownAddress `json:"ccvs"`
		CCVData []protocol.ByteSlice      `json:"ccv_data"`
		Message protocol.Message          `json:"message"`
	}{
		CCVS:    a.CCVS,
		CCVData: ccvData,
		Message: a.Message,
	})
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

type CCVAddressInfo struct {
	RequiredCCVs      []protocol.UnknownAddress `json:"required_ccvs"`
	OptionalCCVs      []protocol.UnknownAddress `json:"optional_ccvs"`
	OptionalThreshold uint8                     `json:"optional_threshold"`
}
