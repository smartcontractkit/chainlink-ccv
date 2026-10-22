package blocks

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const chainID = "11155111"

// fakeOperator records its calls, in order.
type fakeOperator struct {
	calls     []string
	lca       LCA
	lcaErr    error
	removeErr error
}

func (f *fakeOperator) FindLCA(_ context.Context, id int64) (LCA, error) {
	f.calls = append(f.calls, "FindLCA "+strconv.FormatInt(id, 10))
	return f.lca, f.lcaErr
}

func (f *fakeOperator) RemoveFrom(_ context.Context, id, start int64) error {
	f.calls = append(f.calls, "RemoveFrom "+strconv.FormatInt(id, 10)+" "+strconv.FormatInt(start, 10))
	return f.removeErr
}

type harness struct {
	op  *fakeOperator
	out *bytes.Buffer
}

func newHarness() *harness {
	return &harness{op: &fakeOperator{}, out: &bytes.Buffer{}}
}

// run executes `blocks <args>` and returns the command's error.
func (h *harness) run(t *testing.T, args ...string) error {
	t.Helper()
	deps := Deps{Logger: logger.Test(t), Operator: h.op, Stdout: h.out}
	app := cli.NewApp()
	app.Writer = h.out
	app.ErrWriter = h.out
	app.Commands = []cli.Command{{Name: "blocks", Subcommands: InitBlocksCommandsWithFactory(func() Deps { return deps })}}
	return app.Run(append([]string{"verifier", "blocks"}, args...))
}

// The node prints a title, then the row as a divider-framed list with the labels padded.
func TestFindLCAPrintsWhatTheNodePrints(t *testing.T) {
	h := newHarness()
	h.op.lca = LCA{ChainID: "1337", BlockHash: "0xabc", BlockNumber: 42}

	require.NoError(t, h.run(t, "find-lca", "--evm-chain-id", chainID))

	require.Equal(t, []string{"FindLCA " + chainID}, h.op.calls)
	divider := strings.Repeat("-", len("Block Hash:   0xabc")) // the longest line
	want := "Last Common Ancestor\n" +
		"\n" + divider + "\n" +
		"ChainID:      1337\n" +
		"Block Hash:   0xabc\n" +
		"Block Number: 42" +
		"\n" + divider + "\n"
	require.Equal(t, want, h.out.String())
}

func TestFindLCAErrorsNameTheChainIDAndTheCause(t *testing.T) {
	t.Run("operator failure", func(t *testing.T) {
		h := newHarness()
		h.op.lcaErr = errors.New("rpc down")

		err := h.run(t, "find-lca", "--evm-chain-id", chainID)
		require.ErrorContains(t, err, chainID)
		require.ErrorContains(t, err, "rpc down")
		require.Empty(t, h.out.String(), "nothing is printed on failure")
	})
	t.Run("chain ID that is not a number", func(t *testing.T) {
		h := newHarness()

		err := h.run(t, "find-lca", "--evm-chain-id", "sepolia")
		require.ErrorContains(t, err, "sepolia")
		require.Empty(t, h.op.calls)
	})
	t.Run("chain ID missing", func(t *testing.T) {
		h := newHarness()

		require.Error(t, h.run(t, "find-lca"))
		require.Empty(t, h.op.calls)
	})
}

func TestRemoveBlocksRequiresAPositiveStart(t *testing.T) {
	for name, args := range map[string][]string{
		"missing":  {"remove-blocks", "--evm-chain-id", chainID},
		"zero":     {"remove-blocks", "--evm-chain-id", chainID, "--start", "0"},
		"negative": {"remove-blocks", "--evm-chain-id", chainID, "--start", "-5"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness()

			require.Error(t, h.run(t, args...))
			require.Empty(t, h.op.calls, "nothing is deleted before the arguments are valid")
		})
	}
	h := newHarness()
	require.EqualError(t, h.run(t, "remove-blocks", "--evm-chain-id", chainID, "--start", "0"),
		"must pass a positive value in '--start' parameter", "the node's message")
}

func TestRemoveBlocksRequiresTheChainID(t *testing.T) {
	h := newHarness()

	require.Error(t, h.run(t, "remove-blocks", "--start", "10"))
	require.Empty(t, h.op.calls)
}

// Like the node, it asks nothing and deletes at once.
func TestRemoveBlocksDeletesWithoutPromptingOrPreviewing(t *testing.T) {
	h := newHarness()

	require.NoError(t, h.run(t, "remove-blocks", "--evm-chain-id", chainID, "--start", "10"))

	require.Equal(t, []string{"RemoveFrom " + chainID + " 10"}, h.op.calls)
	require.Empty(t, h.out.String())
}

func TestRemoveBlocksReportsADeleteFailure(t *testing.T) {
	h := newHarness()
	h.op.removeErr = errors.New("db gone")

	err := h.run(t, "remove-blocks", "--evm-chain-id", chainID, "--start", "10")
	require.ErrorContains(t, err, chainID)
	require.ErrorContains(t, err, "db gone")
}

func TestRemoveBlocksHelpSaysTheVerifierMustBeStopped(t *testing.T) {
	cmds := InitBlocksCommandsWithFactory(func() Deps { return Deps{} })
	for _, c := range cmds {
		if c.Name == "remove-blocks" {
			require.Contains(t, strings.ToLower(c.Usage+" "+c.Description), "stopped")
			return
		}
	}
	t.Fatal("no remove-blocks command")
}

// --help must work on a machine with no database, so it never builds the dependencies.
func TestHelpDoesNotBuildDependencies(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"find-lca", "--help"}, {"remove-blocks", "--help"}} {
		out := &bytes.Buffer{}
		app := cli.NewApp()
		app.Writer = out
		app.Commands = []cli.Command{{Name: "blocks", Subcommands: InitBlocksCommandsWithFactory(func() Deps {
			t.Fatal("help built the dependencies")
			return Deps{}
		})}}

		require.NoError(t, app.Run(append([]string{"verifier", "blocks"}, args...)))
		require.NotEmpty(t, out.String())
	}
}
