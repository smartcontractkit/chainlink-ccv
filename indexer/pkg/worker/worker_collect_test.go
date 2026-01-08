package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mocks "github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// fake verifier implementation
type fakeVerifierOK struct {
	addr protocol.UnknownAddress
}

func (f *fakeVerifierOK) GetVerifications(ctx context.Context, messageIDs []protocol.Bytes32) (map[protocol.Bytes32]protocol.VerifierResult, error) {
	res := make(map[protocol.Bytes32]protocol.VerifierResult)
	for _, id := range messageIDs {
		res[id] = protocol.VerifierResult{MessageID: id, VerifierSourceAddress: f.addr, Timestamp: time.Now()}
	}
	return res, nil
}

type fakeVerifierErr struct{}

func (f *fakeVerifierErr) GetVerifications(ctx context.Context, messageIDs []protocol.Bytes32) (map[protocol.Bytes32]protocol.VerifierResult, error) {
	return nil, errors.New("verifier error")
}

func TestCollectVerifierResults_SuccessAndError(t *testing.T) {
	lggr := logger.Test(t)

	// create an address and reader
	addr := mustAddr(t, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	vOK := &fakeVerifierOK{addr: addr}
	cfg := &config.VerifierConfig{BatchSize: 1, MaxBatchWaitTime: 10}

	r := readers.NewVerifierReader(context.Background(), vOK, cfg)
	require.NoError(t, r.Start(context.Background()))
	defer r.Close()

	// task with the message id
	mid := protocol.Bytes32{1}
	tsk := &Task{logger: lggr, messageID: mid}

	results := tsk.collectVerifierResults(context.Background(), []*readers.VerifierReader{r})
	require.Len(t, results, 1)
	require.Equal(t, addr.String(), results[0].VerifierResult.VerifierSourceAddress.String())

	// Now test reader that returns error
	rErr := readers.NewVerifierReader(context.Background(), &fakeVerifierErr{}, cfg)
	require.NoError(t, rErr.Start(context.Background()))
	defer rErr.Close()

	res2 := tsk.collectVerifierResults(context.Background(), []*readers.VerifierReader{rErr})
	require.Len(t, res2, 0)
}

func TestLoadVerifierReaders_InvalidAndLoaded(t *testing.T) {
	lggr := logger.Test(t)
	reg := registry.NewVerifierRegistry()

	addr := mustAddr(t, "0x3333333333333333333333333333333333333333")
	// create a dummy verifier reader and add
	r := &readers.VerifierReader{}
	_ = reg.AddVerifier(addr, "v1", r)

	tsk := &Task{registry: reg, logger: lggr}

	addrs := []string{"not-a-hex", addr.String()}
	readersList, loaded, missing := tsk.loadVerifierReaders(addrs)

	require.Len(t, readersList, 1)
	require.Len(t, loaded, 1)
	require.Len(t, missing, 1)
	require.Equal(t, addr.String(), loaded[0])
	require.Equal(t, "not-a-hex", missing[0])
}

func TestGetExistingVerifiers_StorageError(t *testing.T) {
	lggr := logger.Test(t)
	ms := mocks.NewMockIndexerStorage(t)
	ms.On("GetCCVData", mock.Anything, mock.Anything).Return(nil, errors.New("db"))
	tsk := &Task{storage: ms, messageID: protocol.Bytes32{}, logger: lggr}

	_, err := tsk.getExistingVerifiers(context.Background())
	require.Error(t, err)
}

