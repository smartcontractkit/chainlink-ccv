package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func mustAddr(t *testing.T, hex string) protocol.UnknownAddress {
	t.Helper()
	addr, err := protocol.NewUnknownAddressFromHex(hex)
	require.NoError(t, err)
	return addr
}

// TestTask_GetVerifiers verifies getVerifiers returns the lower-cased hex strings
// for MessageCCVAddresses on the task's message.
func TestTask_GetVerifiers(t *testing.T) {
	lggr := logger.Test(t)

	addr1 := mustAddr(t, "0x1111111111111111111111111111111111111111")
	addr2 := mustAddr(t, "0x2222222222222222222222222222222222222222")

	tsk := &Task{
		logger: lggr,
		message: protocol.VerifierResult{
			MessageCCVAddresses: []protocol.UnknownAddress{addr1, addr2},
		},
	}

	got := tsk.getVerifiers()
	require.Len(t, got, 2)
	require.Equal(t, got[0], addr1.String())
	require.Equal(t, got[1], addr2.String())
}

// TestTask_GetExistingAndMissingVerifiers verifies getExistingVerifiers and
// getMissingVerifiers return the correct sets based on storage results.
func TestTask_GetExistingAndMissingVerifiers(t *testing.T) {
	lggr := logger.Test(t)

	ms := mocks.NewMockIndexerStorage(t)
	// storage will return one existing verifier
	addr1 := mustAddr(t, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	addr2 := mustAddr(t, "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	vr := common.VerifierResultWithMetadata{
		VerifierResult: protocol.VerifierResult{VerifierSourceAddress: addr1},
		Metadata:       common.VerifierResultMetadata{},
	}

	// Expect GetCCVData called and return one entry
	ms.On("GetCCVData", mock.Anything, mock.Anything).Return([]common.VerifierResultWithMetadata{vr}, nil)

	tsk := &Task{
		logger:    lggr,
		storage:   ms,
		messageID: protocol.Bytes32{},
		message: protocol.VerifierResult{
			MessageCCVAddresses: []protocol.UnknownAddress{addr1, addr2},
		},
	}

	existing, err := tsk.getExistingVerifiers(context.Background())
	require.NoError(t, err)
	require.Len(t, existing, 1)
	require.Equal(t, addr1.String(), existing[0])

	missing, err := tsk.getMissingVerifiers(context.Background())
	require.NoError(t, err)
	require.Len(t, missing, 1)
	require.Equal(t, addr2.String(), missing[0])
}

// TestTask_LoadVerifierReaders checks loadVerifierReaders correctly loads readers
// from the registry and reports which addresses were loaded vs missing.
func TestTask_LoadVerifierReaders(t *testing.T) {
	lggr := logger.Test(t)

	reg := registry.NewVerifierRegistry()
	addr1 := mustAddr(t, "0x3333333333333333333333333333333333333333")
	addr2 := mustAddr(t, "0x4444444444444444444444444444444444444444")

	// Add a verifier for addr1 only
	_ = reg.AddVerifier(addr1, "v1", &readers.VerifierReader{})

	tsk := &Task{registry: reg, logger: lggr}

	addrs := []string{addr1.String(), addr2.String()}
	readersList, loaded, missing := tsk.loadVerifierReaders(addrs)

	require.Len(t, readersList, 1)
	require.Len(t, loaded, 1)
	require.Len(t, missing, 1)
	require.Equal(t, addr1.String(), loaded[0])
	require.Equal(t, addr2.String(), missing[0])
}

// TestTask_SetMessageStatus_DelegatesToStorage asserts that SetMessageStatus
// correctly calls UpdateMessageStatus on the underlying storage.
func TestTask_SetMessageStatus_DelegatesToStorage(t *testing.T) {
	lggr := logger.Test(t)

	ms := mocks.NewMockIndexerStorage(t)
	msgID := protocol.Bytes32{}
	// Expect UpdateMessageStatus to be called with the messageID and status
	ms.On("UpdateMessageStatus", mock.Anything, msgID, common.MessageSuccessful, "").Return(nil)

	tsk := &Task{storage: ms, messageID: msgID, logger: lggr}
	err := tsk.SetMessageStatus(context.Background(), common.MessageSuccessful, "")
	require.NoError(t, err)
}

// TestLoadVerifierReaders_InvalidAndLoaded ensures invalid hex addresses are
// treated as missing, while valid addresses that are registered are loaded.
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

// TestGetExistingVerifiers_StorageError verifies that getExistingVerifiers
// returns an error when the storage backend fails.
func TestGetExistingVerifiers_StorageError(t *testing.T) {
	lggr := logger.Test(t)
	ms := mocks.NewMockIndexerStorage(t)
	ms.On("GetCCVData", mock.Anything, mock.Anything).Return(nil, errors.New("db"))
	tsk := &Task{storage: ms, messageID: protocol.Bytes32{}, logger: lggr}

	_, err := tsk.getExistingVerifiers(context.Background())
	require.Error(t, err)
}

// TestGetExistingVerifiers_NotFoundReturnsEmpty verifies that getExistingVerifiers
// returns an empty result without error when the storage returns ErrCCVDataNotFound.
// This handles the "discovery only" message case where no verifications exist yet.
func TestGetExistingVerifiers_NotFoundReturnsEmpty(t *testing.T) {
	lggr := logger.Test(t)
	ms := mocks.NewMockIndexerStorage(t)
	ms.On("GetCCVData", mock.Anything, mock.Anything).Return(nil, storage.ErrCCVDataNotFound)
	tsk := &Task{storage: ms, messageID: protocol.Bytes32{}, logger: lggr}

	existing, err := tsk.getExistingVerifiers(context.Background())
	require.NoError(t, err)
	require.Empty(t, existing)
}

// makeReader creates and starts a VerifierReader wired to the provided
// VerifierResultsAPI. Tests use a small batch size so ProcessMessage
// returns quickly and deterministically.
func makeReader(vf protocol.VerifierResultsAPI) *readers.VerifierReader {
	cfg := &config.VerifierConfig{BatchSize: 1, MaxBatchWaitTime: 1}
	r := readers.NewVerifierReader(context.Background(), vf, cfg)
	_ = r.Start(context.Background())
	// Allow the background goroutine to start and begin reading batches.
	// This small sleep avoids a race where ProcessMessage adds to the batch
	// before the reader's run goroutine is listening, which can cause
	// undeterministic timing and intermittent deadlocks in tests.
	time.Sleep(10 * time.Millisecond)
	return r
}

// TestCollectVerifierResults verifies Task.collectVerifierResults behavior
// across several scenarios:
//   - no readers: expect nil result
//   - single successful reader: reader returns a verification and the result
//     is returned with the correct VerifierName metadata
//   - multiple readers where one returns data and another returns an error:
//     ensure successful results are still collected and named correctly
func TestCollectVerifierResults(t *testing.T) {
	lggr := logger.Test(t)
	msg := protocol.VerifierResult{}
	task, err := NewTask(lggr, msg, registry.NewVerifierRegistry(), nil, time.Second)
	require.NoError(t, err)

	mid := task.messageID

	t.Run("no readers", func(t *testing.T) {
		res := task.collectVerifierResults(context.Background(), nil)
		require.Nil(t, res)
	})

	t.Run("single successful reader", func(t *testing.T) {
		// use generated mock for VerifierResultsAPI
		mv := mocks.NewMockVerifierResultsAPI(t)
		vr := protocol.VerifierResult{MessageID: mid, VerifierSourceAddress: protocol.UnknownAddress([]byte{0x1})}
		mv.On("GetVerifications", mock.Anything, mock.Anything).Return(map[protocol.Bytes32]protocol.VerifierResult{mid: vr}, nil)

		r := makeReader(mv)
		defer func() { _ = r.Close() }()

		// register reader name in registry so metadata.VerifierName is set
		reg := registry.NewVerifierRegistry()
		addr, aerr := protocol.NewUnknownAddressFromHex("0x01")
		require.NoError(t, aerr)
		require.NoError(t, reg.AddVerifier(addr, "test-verifier", r))

		// create task with our registry
		task2, err := NewTask(lggr, msg, reg, nil, time.Second)
		require.NoError(t, err)

		res := task2.collectVerifierResults(context.Background(), []*readers.VerifierReader{r})
		require.Len(t, res, 1)
		require.Equal(t, "test-verifier", res[0].Metadata.VerifierName)
		require.Equal(t, mid, res[0].VerifierResult.MessageID)
	})

	t.Run("multiple readers mixed success and error", func(t *testing.T) {
		mv1 := mocks.NewMockVerifierResultsAPI(t)
		vr1 := protocol.VerifierResult{MessageID: mid, VerifierSourceAddress: protocol.UnknownAddress([]byte{0x2})}
		mv1.On("GetVerifications", mock.Anything, mock.Anything).Return(map[protocol.Bytes32]protocol.VerifierResult{mid: vr1}, nil)

		mv2 := mocks.NewMockVerifierResultsAPI(t)
		mv2.On("GetVerifications", mock.Anything, mock.Anything).Return(nil, context.DeadlineExceeded)

		r1 := makeReader(mv1)
		defer func() { _ = r1.Close() }()
		r2 := makeReader(mv2)
		defer func() { _ = r2.Close() }()

		reg := registry.NewVerifierRegistry()
		addr2, aerr := protocol.NewUnknownAddressFromHex("0x02")
		require.NoError(t, aerr)
		require.NoError(t, reg.AddVerifier(addr2, "verifier-2", r1))

		task3, err := NewTask(lggr, msg, reg, nil, time.Second)
		require.NoError(t, err)

		res := task3.collectVerifierResults(context.Background(), []*readers.VerifierReader{r1, r2})
		require.Len(t, res, 1)
		require.Equal(t, "verifier-2", res[0].Metadata.VerifierName)
	})
}
