package verifier

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

const selectionSelector = protocol.ChainSelector(5009297550715157269)

type finalityReader struct {
	chainaccess.SourceReader
}

func (finalityReader) FinalityViolated() bool { return false }

// spyAccessor records the order of the calls selectChainReader makes on it.
type spyAccessor struct {
	*mocks.MockAccessor
	calls  *[]string
	reader chainaccess.SourceReader
}

func (a *spyAccessor) SourceReader() (chainaccess.SourceReader, error) {
	*a.calls = append(*a.calls, "SourceReader")
	return a.reader, nil
}

// setterAccessor is a spyAccessor that also takes source reader dependencies.
type setterAccessor struct {
	*spyAccessor
	setErr     error
	gotDB      *sql.DB
	gotVerifID string
}

func (a *setterAccessor) SetSourceReaderDeps(db *sql.DB, verifierID string) error {
	*a.calls = append(*a.calls, "SetSourceReaderDeps")
	a.gotDB, a.gotVerifID = db, verifierID
	return a.setErr
}

type spyFactory struct {
	calls    *[]string
	accessor chainaccess.Accessor
	err      error
}

func (f spyFactory) GetAccessor(context.Context, protocol.ChainSelector) (chainaccess.Accessor, error) {
	*f.calls = append(*f.calls, "GetAccessor")
	return f.accessor, f.err
}

type selectionHarness struct {
	t     *testing.T
	calls []string
	spy   *spyAccessor
}

func newSelectionHarness(t *testing.T, reader chainaccess.SourceReader) *selectionHarness {
	t.Helper()
	h := &selectionHarness{t: t}
	h.spy = &spyAccessor{MockAccessor: mocks.NewMockAccessor(t), calls: &h.calls, reader: reader}
	return h
}

func (h *selectionHarness) selectReader(accessor chainaccess.Accessor, logPollerOn, finalityDisabled bool, db *sql.DB) (*chainReader, error) {
	h.t.Helper()
	return selectChainReader(
		h.t.Context(), logger.Test(h.t), spyFactory{calls: &h.calls, accessor: accessor},
		selectionSelector, logPollerOn, db, "verifier-1", finalityDisabled,
	)
}

func TestSelectChainReaderFlagOnSetsDepsBetweenAccessorAndReader(t *testing.T) {
	t.Parallel()

	h := newSelectionHarness(t, finalityReader{SourceReader: mocks.NewMockSourceReader(t)})
	accessor := &setterAccessor{spyAccessor: h.spy}
	db := &sql.DB{}

	got, err := h.selectReader(accessor, true, false, db)
	require.NoError(t, err)
	require.Equal(t, []string{"GetAccessor", "SetSourceReaderDeps", "SourceReader"}, h.calls)
	require.Same(t, db, accessor.gotDB)
	require.Equal(t, "verifier-1", accessor.gotVerifID)
	require.Equal(t, h.spy.reader, got.reader)
	require.NotNil(t, got.finalityReporter)
}

func TestSelectChainReaderFlagOffNeverCallsTheSetter(t *testing.T) {
	t.Parallel()

	h := newSelectionHarness(t, mocks.NewMockSourceReader(t))
	accessor := &setterAccessor{spyAccessor: h.spy, setErr: errors.New("must not be called")}

	got, err := h.selectReader(accessor, false, false, &sql.DB{})
	require.NoError(t, err)
	require.Equal(t, []string{"GetAccessor", "SourceReader"}, h.calls)
	require.Nil(t, got.finalityReporter)
}

func TestSelectChainReaderAccessorWithoutSetterKeepsTheRPCReader(t *testing.T) {
	t.Parallel()

	h := newSelectionHarness(t, mocks.NewMockSourceReader(t))

	got, err := h.selectReader(h.spy, true, false, &sql.DB{})
	require.NoError(t, err)
	require.Equal(t, []string{"GetAccessor", "SourceReader"}, h.calls)
	require.Same(t, h.spy.reader, got.reader)
	require.Nil(t, got.finalityReporter)
}

func TestSelectChainReaderSetterFailureSkipsTheChainWithoutFallback(t *testing.T) {
	t.Parallel()

	h := newSelectionHarness(t, mocks.NewMockSourceReader(t))
	wantErr := errors.New("guard held by another runtime")
	accessor := &setterAccessor{spyAccessor: h.spy, setErr: wantErr}

	_, err := h.selectReader(accessor, true, false, &sql.DB{})
	require.ErrorIs(t, err, wantErr)
	require.ErrorContains(t, err, selectionSelector.String())
	require.Equal(t, []string{"GetAccessor", "SetSourceReaderDeps"}, h.calls, "the RPC reader must not be requested")
}

func TestSelectChainReaderDisabledFinalityCheckGetsNoReporter(t *testing.T) {
	t.Parallel()

	h := newSelectionHarness(t, finalityReader{SourceReader: mocks.NewMockSourceReader(t)})
	accessor := &setterAccessor{spyAccessor: h.spy}

	got, err := h.selectReader(accessor, true, true, &sql.DB{})
	require.NoError(t, err)
	require.Nil(t, got.finalityReporter)
}

func TestSelectChainReaderLogPollerReaderWithoutReporterIsAnError(t *testing.T) {
	t.Parallel()

	h := newSelectionHarness(t, mocks.NewMockSourceReader(t))
	accessor := &setterAccessor{spyAccessor: h.spy}

	_, err := h.selectReader(accessor, true, false, &sql.DB{})
	require.ErrorContains(t, err, selectionSelector.String())
	require.ErrorContains(t, err, "finality")
}

func TestSelectChainReaderAccessorFailure(t *testing.T) {
	t.Parallel()

	var calls []string
	wantErr := errors.New("dial failed")
	_, err := selectChainReader(
		t.Context(), logger.Test(t), spyFactory{calls: &calls, err: wantErr},
		selectionSelector, true, &sql.DB{}, "verifier-1", false,
	)
	require.ErrorIs(t, err, wantErr)
	require.Equal(t, []string{"GetAccessor"}, calls)
}
