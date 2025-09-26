package verifier

import (
	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// sourceState manages state for a single source chain reader.
type sourceState struct {
	reader              SourceReader
	verificationTaskCh  <-chan VerificationTask
	verificationErrorCh chan VerificationError
	chainSelector       protocol.ChainSelector
}

// newSourceState creates a new source state.
func newSourceState(chainSelector protocol.ChainSelector, reader SourceReader) *sourceState {
	return &sourceState{
		chainSelector:       chainSelector,
		reader:              reader,
		verificationTaskCh:  reader.VerificationTaskChannel(),
		verificationErrorCh: make(chan VerificationError, 100), // Buffered error channel
	}
}
