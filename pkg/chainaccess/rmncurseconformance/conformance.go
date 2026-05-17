package rmncurseconformance

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// RMNCurseHarness mutates on-chain (or in-chain) RMN Remote curse state for
// tests. It is not part of [chainaccess.RMNCurseReader]. Implementations are
// chain-specific; EVM can deploy RMNRemote, [CurseRMN] via Curse, and
// [ClearRMNCurses] via Uncurse.
type RMNCurseHarness interface {
	// DeployRMN deploys or ensures an RMN Remote–equivalent and returns the
	// address the [chainaccess.RMNCurseReader] under test must use. Second
	// and later calls may return the same address if idempotent, or an error
	// if a second deploy is not supported.
	DeployRMN(ctx context.Context) (rmnAddress protocol.UnknownAddress, err error)
	// CurseRMN curses the given subjects (e.g. chain selectors or global
	// curse as [protocol.Bytes16]).
	CurseRMN(ctx context.Context, subjects []protocol.Bytes16) error
	// ClearRMNCurses removes all curses so a subsequent
	// [chainaccess.RMNCurseReader.GetRMNCursedSubjects] returns the empty
	// slice (or the chain’s pre-curse baseline). Safe to call when already clear.
	ClearRMNCurses(ctx context.Context) error
}

// NewReaderFn builds a [chainaccess.RMNCurseReader] for the contract at
// rmnAddress, which must be the one returned from [RMNCurseHarness.DeployRMN].
type NewReaderFn func(ctx context.Context, rmnAddress protocol.UnknownAddress) (chainaccess.RMNCurseReader, error)

// Config drives [Run]. Cases nil uses [DefaultCases].
type Config struct {
	Harness   RMNCurseHarness
	NewReader NewReaderFn
	// Cases custom matrix; if nil, [DefaultCases] is used.
	Cases []Case
}

// Case is one apply→read round-trip (clear is done before/after in [Run]).
type Case struct {
	Name    string
	Subjects []protocol.Bytes16
}

// DefaultCases is a small baseline used when [Config.Cases] is nil.
func DefaultCases() []Case {
	return []Case{
		{
			Name:    "three_distinct_subjects",
			Subjects: threeSampleSubjects(),
		},
	}
}

func threeSampleSubjects() []protocol.Bytes16 {
	// Non-global, non-zero, distinct [16]byte chain-subject stand-ins.
	return []protocol.Bytes16{
		subjectWithSuffix(0x11),
		subjectWithSuffix(0x22),
		subjectWithSuffix(0x33),
	}
}

func subjectWithSuffix(b byte) (s protocol.Bytes16) {
	s[15] = b
	return s
}

// Run deploys (via harness), builds the reader, then for each [Case] clears,
// curses the expected set, checks [chainaccess.RMNCurseReader.GetRMNCursedSubjects]
// (order-independent), and clears again. A nil ctx uses [context.Background].
func Run(t *testing.T, ctx context.Context, cfg Config) {
	t.Helper()
	if ctx == nil {
		ctx = context.Background()
	}
	require.NotNil(t, cfg.Harness, "Harness")
	require.NotNil(t, cfg.NewReader, "NewReader")

	cases := cfg.Cases
	if len(cases) == 0 {
		cases = DefaultCases()
	}

	rmnAddr, err := cfg.Harness.DeployRMN(ctx)
	require.NoError(t, err, "DeployRMN")
	if len(rmnAddr) == 0 {
		require.Fail(t, "DeployRMN returned empty UnknownAddress")
	}

	reader, err := cfg.NewReader(ctx, rmnAddr)
	require.NoError(t, err, "NewReader")
	require.NotNil(t, reader, "NewReader must not return a nil interface value")

	for _, c := range cases {
		if c.Name == "" {
			c.Name = "unnamed_case"
		}
		t.Run(c.Name, func(t *testing.T) {
			t.Helper()
			err := cfg.Harness.ClearRMNCurses(ctx)
			require.NoError(t, err, "ClearRMNCurses (start)")

			got, err := reader.GetRMNCursedSubjects(ctx)
			require.NoError(t, err, "GetRMNCursedSubjects after clear")
			require.Empty(t, got, "subjects should be empty after clear")

			err = cfg.Harness.CurseRMN(ctx, c.Subjects)
			require.NoError(t, err, "CurseRMN")

			got, err = reader.GetRMNCursedSubjects(ctx)
			require.NoError(t, err, "GetRMNCursedSubjects after curse")
			// On-chain getCursedSubjects order is not specified; assert multiset match.
			require.ElementsMatch(t, c.Subjects, got, "cursed subjects")

			err = cfg.Harness.ClearRMNCurses(ctx)
			require.NoError(t, err, "ClearRMNCurses (end)")
		})
	}
}
