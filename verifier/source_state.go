package verifier

import (
	reader2 "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/reader"
	"github.com/smartcontractkit/chainlink-ccv/verifier/types"
	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
)

// sourceState manages state for a single source chain reader
type sourceState struct {
	chainSelector       cciptypes.ChainSelector
	reader              reader2.SourceReader
	verificationTaskCh  <-chan types.VerificationTask
	verificationErrorCh chan types.VerificationError
}

// newSourceState creates a new source state
func newSourceState(chainSelector cciptypes.ChainSelector, reader reader2.SourceReader) *sourceState {
	return &sourceState{
		chainSelector:       chainSelector,
		reader:              reader,
		verificationTaskCh:  reader.VerificationTaskChannel(),
		verificationErrorCh: make(chan types.VerificationError, 100), // Buffered error channel
	}
}
