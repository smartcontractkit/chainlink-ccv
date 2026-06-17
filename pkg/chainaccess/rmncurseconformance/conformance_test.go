package rmncurseconformance_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess/rmncurseconformance"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// fakeReader implements [chainaccess.RMNCurseReader] using state from [fakeHarness].
type fakeReader struct{ h *fakeHarness }

func (f *fakeReader) GetRMNCursedSubjects(_ context.Context) ([]protocol.Bytes16, error) {
	if f == nil || f.h == nil {
		return nil, nil
	}
	return append([]protocol.Bytes16{}, f.h.cursed...), nil
}

// fakeHarness implements [rmncurseconformance.RMNCurseHarness] in memory.
type fakeHarness struct {
	cursed  []protocol.Bytes16
	rmnAddr protocol.UnknownAddress
	persist bool
}

func (f *fakeHarness) DeployRMN(_ context.Context) (protocol.UnknownAddress, error) {
	if f.persist && len(f.rmnAddr) > 0 {
		return f.rmnAddr, nil
	}
	f.rmnAddr = protocol.UnknownAddress{0x1: 0xab, 19: 0xcc}
	return f.rmnAddr, nil
}

func (f *fakeHarness) CurseRMN(_ context.Context, subjects []protocol.Bytes16) error {
	f.cursed = append(f.cursed[:0], subjects...)
	return nil
}

func (f *fakeHarness) ClearRMNCurses(_ context.Context) error {
	f.cursed = nil
	return nil
}

func TestRun_fakes(t *testing.T) {
	f := &fakeHarness{persist: true}
	rmncurseconformance.Run(t, context.Background(), rmncurseconformance.Config{
		Harness: f,
		NewReader: func(_ context.Context, rmn protocol.UnknownAddress) (chainaccess.RMNCurseReader, error) {
			_ = rmn
			return &fakeReader{h: f}, nil
		},
	})
}

func TestDefaultCases_subjectShape(t *testing.T) {
	c := rmncurseconformance.DefaultCases()
	require.Greater(t, len(c[0].Subjects), 0)
}
