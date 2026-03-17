package chainstatuses

import (
	"context"
	"io"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const cmdNameList = "list"

type fakeStore struct {
	rows    []chainstatus.Row
	listErr error
	setErr  error
}

func (f *fakeStore) List(ctx context.Context) ([]chainstatus.Row, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.rows, nil
}

func (f *fakeStore) SetDisabled(ctx context.Context, chainSelector protocol.ChainSelector, verifierID string, disabled bool) error {
	return f.setErr
}

func (f *fakeStore) SetFinalizedBlockHeight(ctx context.Context, chainSelector protocol.ChainSelector, verifierID string, height *big.Int) error {
	return f.setErr
}

func TestInitCCVChainStatusesCommands_returns_four_commands(t *testing.T) {
	deps := Deps{Logger: logger.Test(t), Store: &fakeStore{}}
	cmds := InitCCVChainStatusesCommands(deps)
	require.Len(t, cmds, 4)
	names := make([]string, len(cmds))
	for i, c := range cmds {
		names[i] = c.Name
	}
	assert.Equal(t, []string{"list", "enable", "disable", "set-finalized-height"}, names)
}

func TestListAction_empty_store_prints_no_rows_message(t *testing.T) {
	deps := Deps{Logger: logger.Test(t), Store: &fakeStore{rows: nil}}
	cmds := InitCCVChainStatusesCommands(deps)
	var listCmd *cli.Command
	for i := range cmds {
		if cmds[i].Name == cmdNameList {
			listCmd = &cmds[i]
			break
		}
	}
	require.NotNil(t, listCmd)
	app := cli.NewApp()
	app.Commands = []cli.Command{*listCmd}
	err := app.Run([]string{"chainlink", cmdNameList})
	require.NoError(t, err)
}

func TestListAction_with_rows_prints_tsv(t *testing.T) {
	now := time.Now().UTC()
	deps := Deps{
		Logger: logger.Test(t),
		Store: &fakeStore{
			rows: []chainstatus.Row{
				{
					ChainSelector:        1,
					VerifierID:           "v1",
					FinalizedBlockHeight: big.NewInt(100),
					Disabled:             false,
					UpdatedAt:            now,
				},
			},
		},
	}
	cmds := InitCCVChainStatusesCommands(deps)
	var listCmd *cli.Command
	for i := range cmds {
		if cmds[i].Name == cmdNameList {
			listCmd = &cmds[i]
			break
		}
	}
	require.NotNil(t, listCmd)
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()
	app := cli.NewApp()
	app.Commands = []cli.Command{*listCmd}
	go func() {
		_ = app.Run([]string{"chainlink", cmdNameList})
		_ = w.Close()
	}()
	outBytes, err := io.ReadAll(r)
	require.NoError(t, err)
	out := string(outBytes)
	assert.Contains(t, out, "Chain")
	assert.Contains(t, out, "Chain Selector")
	assert.Contains(t, out, "1")
	assert.Contains(t, out, "v1")
	assert.Contains(t, out, "100")
	assert.Contains(t, out, "false")
}

func TestListAction_store_error_returns_error(t *testing.T) {
	deps := Deps{
		Logger: logger.Test(t),
		Store:  &fakeStore{listErr: assert.AnError},
	}
	cmds := InitCCVChainStatusesCommands(deps)
	var listCmd *cli.Command
	for i := range cmds {
		if cmds[i].Name == cmdNameList {
			listCmd = &cmds[i]
			break
		}
	}
	require.NotNil(t, listCmd)
	app := cli.NewApp()
	app.Commands = []cli.Command{*listCmd}
	err := app.Run([]string{"chainlink", cmdNameList})
	require.Error(t, err)
}

func TestParseChainSelector_valid_returns_selector(t *testing.T) {
	sel, err := ParseChainSelector("123")
	require.NoError(t, err)
	assert.Equal(t, protocol.ChainSelector(123), sel)
}

func TestParseChainSelector_invalid_returns_error(t *testing.T) {
	_, err := ParseChainSelector("abc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid chain selector")
}
