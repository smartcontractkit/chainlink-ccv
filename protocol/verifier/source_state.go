package verifier

import (
	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
)

// sourceState represents the state of a single source reader
type sourceState struct {
	chainSelector      cciptypes.ChainSelector
	reader             SourceReader
	verificationTaskCh <-chan common.VerificationTask
}

func newSourceState(chainSelector cciptypes.ChainSelector, reader SourceReader) *sourceState {
	return &sourceState{
		chainSelector:      chainSelector,
		reader:             reader,
		verificationTaskCh: reader.MessagesChannel(),
	}
}
