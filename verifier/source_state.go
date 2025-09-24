package verifier

import (
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/reader"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// sourceState manages state for a single source chain reader.
type sourceState struct {
	reader              reader.SourceReader
	verificationTaskCh  <-chan types.VerificationTask
	verificationErrorCh chan types.VerificationError
	chainSelector       protocol.ChainSelector
}

// newSourceState creates a new source state.
func newSourceState(chainSelector protocol.ChainSelector, reader reader.SourceReader) *sourceState {
	return &sourceState{
		chainSelector:       chainSelector,
		reader:              reader,
		verificationTaskCh:  reader.VerificationTaskChannel(),
		verificationErrorCh: make(chan types.VerificationError, 100), // Buffered error channel
	}
}
