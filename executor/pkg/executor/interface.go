package executor

import (
	"context"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
)

type Executor interface {
	ExecuteMessage(ctx context.Context, messageWithCCVData types.MessageWithCCVData) error
	CheckValidMessage(ctx context.Context, messageWithCCVData types.MessageWithCCVData) error
}
