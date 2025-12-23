package verifier_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/verifier"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/mocks"
)

func Test_MessageSent(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	outCh := make(chan batcher.BatchResult[verifier.VerificationTask], 10)
	fakeFanout := FakeSourceReaderFanout{
		batcher: batcher.NewBatcher[verifier.VerificationTask](
			ctx,
			5,
			100*time.Millisecond,
			outCh,
		),
		outCh: outCh,
	}

	ver := mocks.NewMockVerifier(t)
	fmt.Println(fakeFanout)
	fmt.Println(ver)
}

type FakeSourceReaderFanout struct {
	batcher *batcher.Batcher[verifier.VerificationTask]
	outCh   chan batcher.BatchResult[verifier.VerificationTask]
}

func (f FakeSourceReaderFanout) RetryTasks(minDelay time.Duration, tasks ...verifier.VerificationTask) error {
	return f.batcher.Retry(minDelay, tasks...)
}

func (f FakeSourceReaderFanout) ReadyTasksChannel() <-chan batcher.BatchResult[verifier.VerificationTask] {
	return f.outCh
}
