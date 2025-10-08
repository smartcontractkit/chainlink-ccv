package verifier

import (
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// sourceState manages state for a single source chain reader.
type sourceState struct {
	reader              *SourceReaderService
	verificationTaskCh  <-chan VerificationTask
	verificationErrorCh chan VerificationError
	chainSelector       protocol.ChainSelector
}

// newSourceState creates a new source state.
func newSourceState(chainSelector protocol.ChainSelector, reader SourceReader) *sourceState {
	// TODO: Wrap SourceReader in a SourceReaderService to manage lifecycle.
	return &sourceState{
		chainSelector: chainSelector,
		reader:        nil,
		//verificationTaskCh:  reader.VerificationTaskChannel(),
		verificationErrorCh: make(chan VerificationError, 100), // Buffered error channel
	}
}
