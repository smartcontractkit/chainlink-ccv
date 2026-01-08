package worker

import (
	"context"
	"testing"

	"github.com/pkg/errors"
	testmock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	mocks "github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func mustAddr(t *testing.T, hex string) protocol.UnknownAddress {
	t.Helper()
	addr, err := protocol.NewUnknownAddressFromHex(hex)
	require.NoError(t, err)
	return addr
}

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
	ms.On("GetCCVData", testmock.Anything, testmock.Anything).Return([]common.VerifierResultWithMetadata{vr}, nil)

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

func TestTask_SetMessageStatus_DelegatesToStorage(t *testing.T) {
	lggr := logger.Test(t)

	ms := mocks.NewMockIndexerStorage(t)
	msgID := protocol.Bytes32{}
	// Expect UpdateMessageStatus to be called with the messageID and status
	ms.On("UpdateMessageStatus", testmock.Anything, msgID, common.MessageSuccessful, "").Return(nil)

	tsk := &Task{storage: ms, messageID: msgID, logger: lggr}
	err := tsk.SetMessageStatus(context.Background(), common.MessageSuccessful, "")
	require.NoError(t, err)
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
	ms.On("GetCCVData", testmock.Anything, testmock.Anything).Return(nil, errors.New("db"))
	tsk := &Task{storage: ms, messageID: protocol.Bytes32{}, logger: lggr}

	_, err := tsk.getExistingVerifiers(context.Background())
	require.Error(t, err)
}
