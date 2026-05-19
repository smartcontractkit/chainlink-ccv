package headtrackerconformance_test

import (
	"context"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess/headtrackerconformance"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// fakeHT is a minimal chainaccess.HeadTracker for self-tests of the harness.
type fakeHT struct {
	latest, finalized, safe *protocol.BlockHeader
	// safeMode: 0 = (nil, nil) for safe; 1 = return f.safe; 2 = (nil, nil) for safe must be nil; 3 = return f.safe (alias of 1)
	safeMode int
}

func (f *fakeHT) LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error) {
	return f.latest, f.finalized, nil
}

func (f *fakeHT) LatestSafeBlock(ctx context.Context) (safe *protocol.BlockHeader, err error) {
	switch f.safeMode {
	case 0, 2:
		return nil, nil
	case 1, 3:
		return f.safe, nil
	default:
		return f.safe, nil
	}
}

// fakeNumberOracle is a [headtrackerconformance.Oracle] for tests.
type fakeNumberOracle struct {
	headersByNumber map[uint64]*protocol.BlockHeader
	errByNumber     map[uint64]error
}

func (f *fakeNumberOracle) BlockHeaderByNumber(ctx context.Context, number uint64) (*protocol.BlockHeader, error) {
	if f.errByNumber != nil {
		if e, ok := f.errByNumber[number]; ok {
			return nil, e
		}
	}
	h := f.headersByNumber[number]
	if h == nil {
		return nil, errNoSuchBlock
	}
	return h, nil
}

var errNoSuchBlock = errFake("no such block")

type errFake string

func (e errFake) Error() string { return string(e) }

func b(n uint64, h0, p0 byte) *protocol.BlockHeader {
	var hash, parent protocol.Bytes32
	hash[0] = h0
	parent[0] = p0
	return &protocol.BlockHeader{
		Number:     n,
		Hash:       hash,
		ParentHash: parent,
		Timestamp:  time.Unix(1700000000+int64(n), 0).UTC(),
	}
}

func TestRun_passesForMatchingFakes_SafeAny_nilSafe(t *testing.T) {
	latest := b(100, 1, 9)
	fin := b(90, 2, 8)
	m := map[uint64]*protocol.BlockHeader{100: latest, 90: fin, 95: b(95, 3, 2)}
	ht := &fakeHT{latest: latest, finalized: fin, safe: m[95], safeMode: 0}
	oracle := &fakeNumberOracle{headersByNumber: m}

	headtrackerconformance.Run(t, context.Background(), headtrackerconformance.Config{
		HeadTracker: ht,
		Oracle:      oracle,
		Safe:        headtrackerconformance.SafeAny,
	})
}

func TestRun_SafeAny_nonNilSafe(t *testing.T) {
	latest := b(100, 1, 9)
	fin := b(90, 2, 8)
	safe := b(95, 3, 2)
	m := map[uint64]*protocol.BlockHeader{100: latest, 90: fin, 95: safe}
	ht := &fakeHT{latest: latest, finalized: fin, safe: safe, safeMode: 1}
	oracle := &fakeNumberOracle{headersByNumber: m}

	headtrackerconformance.Run(t, context.Background(), headtrackerconformance.Config{
		HeadTracker: ht,
		Oracle:      oracle,
		Safe:        headtrackerconformance.SafeAny,
	})
}

func TestRun_SafeMustBeNil(t *testing.T) {
	latest := b(10, 1, 0)
	fin := b(5, 2, 0)
	m := map[uint64]*protocol.BlockHeader{10: latest, 5: fin}
	ht := &fakeHT{latest: latest, finalized: fin, safeMode: 2}
	oracle := &fakeNumberOracle{headersByNumber: m}

	headtrackerconformance.Run(t, context.Background(), headtrackerconformance.Config{
		HeadTracker: ht,
		Oracle:      oracle,
		Safe:        headtrackerconformance.SafeMustBeNil,
	})
}

func TestRun_SafeMustBePresent(t *testing.T) {
	latest := b(100, 1, 9)
	fin := b(90, 2, 8)
	safe := b(95, 3, 2)
	m := map[uint64]*protocol.BlockHeader{100: latest, 90: fin, 95: safe}
	ht := &fakeHT{latest: latest, finalized: fin, safe: safe, safeMode: 1}
	oracle := &fakeNumberOracle{headersByNumber: m}

	headtrackerconformance.Run(t, context.Background(), headtrackerconformance.Config{
		HeadTracker: ht,
		Oracle:      oracle,
		Safe:        headtrackerconformance.SafeMustBePresent,
	})
}
