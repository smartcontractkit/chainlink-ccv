package executor

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"
)

type Executor interface {
	// ExecuteMessage executes the message
	ExecuteMessage(ctx context.Context, messageWithCCVData types.MessageWithCCVData) error
	// CheckValidMessage checks that message is valid
	CheckValidMessage(ctx context.Context, messageWithCCVData types.MessageWithCCVData) error
}
