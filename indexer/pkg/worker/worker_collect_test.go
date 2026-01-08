package worker

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

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
