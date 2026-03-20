package chainstatuses

import (
	"io"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-ccv/cli/chainstatuses/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	cmdNameList               = "list"
	cmdNameEnable             = "enable"
	cmdNameDisable            = "disable"
	cmdNameSetFinalizedHeight = "set-finalized-height"
)

func findCmd(cmds []cli.Command, name string) *cli.Command {
	for i := range cmds {
		if cmds[i].Name == name {
			return &cmds[i]
		}
	}
	return nil
}

func TestInitCCVChainStatusesCommands_returns_four_commands(t *testing.T) {
	store := mocks.NewMockChainStatusStore(t)
	deps := Deps{Logger: logger.Test(t), Store: store}
	cmds := InitCCVChainStatusesCommands(deps)
	require.Len(t, cmds, 4)
	names := make([]string, len(cmds))
	for i, c := range cmds {
		names[i] = c.Name
	}
	assert.Equal(t, []string{"list", "enable", "disable", "set-finalized-height"}, names)
}

func TestListAction_empty_store_prints_no_rows_message(t *testing.T) {
	store := mocks.NewMockChainStatusStore(t)
	store.EXPECT().List(mock.Anything).Return(nil, nil).Once()
	deps := Deps{Logger: logger.Test(t), Store: store}
	cmds := InitCCVChainStatusesCommands(deps)
	listCmd := findCmd(cmds, cmdNameList)
	require.NotNil(t, listCmd)
	app := cli.NewApp()
	app.Commands = []cli.Command{*listCmd}
	err := app.Run([]string{"chainlink", cmdNameList})
	require.NoError(t, err)
}

func TestListAction_with_rows_prints_tsv(t *testing.T) {
	now := time.Now().UTC()
	rows := []chainstatus.Row{
		{
			ChainSelector:        1,
			VerifierID:           "v1",
			FinalizedBlockHeight: big.NewInt(100),
			Disabled:             false,
			UpdatedAt:            now,
		},
	}
	store := mocks.NewMockChainStatusStore(t)
	store.EXPECT().List(mock.Anything).Return(rows, nil).Once()
	deps := Deps{Logger: logger.Test(t), Store: store}
	cmds := InitCCVChainStatusesCommands(deps)
	listCmd := findCmd(cmds, cmdNameList)
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
	store := mocks.NewMockChainStatusStore(t)
	store.EXPECT().List(mock.Anything).Return(nil, assert.AnError).Once()
	deps := Deps{Logger: logger.Test(t), Store: store}
	cmds := InitCCVChainStatusesCommands(deps)
	listCmd := findCmd(cmds, cmdNameList)
	require.NotNil(t, listCmd)
	app := cli.NewApp()
	app.Commands = []cli.Command{*listCmd}
	err := app.Run([]string{"chainlink", cmdNameList})
	require.Error(t, err)
}

func TestEnableAction_calls_store_with_correct_args_and_succeeds(t *testing.T) {
	store := mocks.NewMockChainStatusStore(t)
	store.EXPECT().
		SetDisabled(mock.Anything, protocol.ChainSelector(456), "my-verifier", false).
		Return(nil).Once()
	deps := Deps{Logger: logger.Test(t), Store: store}
	cmds := InitCCVChainStatusesCommands(deps)
	enableCmd := findCmd(cmds, cmdNameEnable)
	require.NotNil(t, enableCmd)
	app := cli.NewApp()
	app.Commands = []cli.Command{*enableCmd}
	err := app.Run([]string{"chainlink", cmdNameEnable, "--chain-selector", "456", "--verifier-id", "my-verifier"})
	require.NoError(t, err)
}

func TestEnableAction_store_error_returns_error(t *testing.T) {
	store := mocks.NewMockChainStatusStore(t)
	store.EXPECT().
		SetDisabled(mock.Anything, protocol.ChainSelector(1), "v1", false).
		Return(assert.AnError).Once()
	deps := Deps{Logger: logger.Test(t), Store: store}
	cmds := InitCCVChainStatusesCommands(deps)
	enableCmd := findCmd(cmds, cmdNameEnable)
	require.NotNil(t, enableCmd)
	app := cli.NewApp()
	app.Commands = []cli.Command{*enableCmd}
	err := app.Run([]string{"chainlink", cmdNameEnable, "--chain-selector", "1", "--verifier-id", "v1"})
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}

func TestEnableAction_invalid_chain_selector_returns_error(t *testing.T) {
	store := mocks.NewMockChainStatusStore(t)
	deps := Deps{Logger: logger.Test(t), Store: store}
	cmds := InitCCVChainStatusesCommands(deps)
	enableCmd := findCmd(cmds, cmdNameEnable)
	require.NotNil(t, enableCmd)
	app := cli.NewApp()
	app.Commands = []cli.Command{*enableCmd}
	err := app.Run([]string{"chainlink", cmdNameEnable, "--chain-selector", "abc", "--verifier-id", "v1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid chain selector")
}

func TestDisableAction_calls_store_with_correct_args_and_succeeds(t *testing.T) {
	store := mocks.NewMockChainStatusStore(t)
	store.EXPECT().
		SetDisabled(mock.Anything, protocol.ChainSelector(789), "v2", true).
		Return(nil).Once()
	deps := Deps{Logger: logger.Test(t), Store: store}
	cmds := InitCCVChainStatusesCommands(deps)
	disableCmd := findCmd(cmds, cmdNameDisable)
	require.NotNil(t, disableCmd)
	app := cli.NewApp()
	app.Commands = []cli.Command{*disableCmd}
	err := app.Run([]string{"chainlink", cmdNameDisable, "--chain-selector", "789", "--verifier-id", "v2"})
	require.NoError(t, err)
}

func TestDisableAction_store_error_returns_error(t *testing.T) {
	store := mocks.NewMockChainStatusStore(t)
	store.EXPECT().
		SetDisabled(mock.Anything, protocol.ChainSelector(1), "v1", true).
		Return(assert.AnError).Once()
	deps := Deps{Logger: logger.Test(t), Store: store}
	cmds := InitCCVChainStatusesCommands(deps)
	disableCmd := findCmd(cmds, cmdNameDisable)
	require.NotNil(t, disableCmd)
	app := cli.NewApp()
	app.Commands = []cli.Command{*disableCmd}
	err := app.Run([]string{"chainlink", cmdNameDisable, "--chain-selector", "1", "--verifier-id", "v1"})
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}

func TestSetFinalizedHeightAction_calls_store_with_correct_args_and_succeeds(t *testing.T) {
	store := mocks.NewMockChainStatusStore(t)
	store.EXPECT().
		SetFinalizedBlockHeight(mock.Anything, protocol.ChainSelector(789), "v2", big.NewInt(42)).
		Return(nil).Once()
	deps := Deps{Logger: logger.Test(t), Store: store}
	cmds := InitCCVChainStatusesCommands(deps)
	setHeightCmd := findCmd(cmds, cmdNameSetFinalizedHeight)
	require.NotNil(t, setHeightCmd)
	app := cli.NewApp()
	app.Commands = []cli.Command{*setHeightCmd}
	err := app.Run([]string{"chainlink", cmdNameSetFinalizedHeight, "--chain-selector", "789", "--verifier-id", "v2", "--block-height", "42"})
	require.NoError(t, err)
}

func TestSetFinalizedHeightAction_store_error_returns_error(t *testing.T) {
	store := mocks.NewMockChainStatusStore(t)
	store.EXPECT().
		SetFinalizedBlockHeight(mock.Anything, protocol.ChainSelector(1), "v1", big.NewInt(100)).
		Return(assert.AnError).Once()
	deps := Deps{Logger: logger.Test(t), Store: store}
	cmds := InitCCVChainStatusesCommands(deps)
	setHeightCmd := findCmd(cmds, cmdNameSetFinalizedHeight)
	require.NotNil(t, setHeightCmd)
	app := cli.NewApp()
	app.Commands = []cli.Command{*setHeightCmd}
	err := app.Run([]string{"chainlink", cmdNameSetFinalizedHeight, "--chain-selector", "1", "--verifier-id", "v1", "--block-height", "100"})
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}

func TestSetFinalizedHeightAction_invalid_chain_selector_returns_error(t *testing.T) {
	store := mocks.NewMockChainStatusStore(t)
	deps := Deps{Logger: logger.Test(t), Store: store}
	cmds := InitCCVChainStatusesCommands(deps)
	setHeightCmd := findCmd(cmds, cmdNameSetFinalizedHeight)
	require.NotNil(t, setHeightCmd)
	app := cli.NewApp()
	app.Commands = []cli.Command{*setHeightCmd}
	err := app.Run([]string{"chainlink", cmdNameSetFinalizedHeight, "--chain-selector", "xyz", "--verifier-id", "v1", "--block-height", "1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid chain selector")
}

func TestSetFinalizedHeightAction_missing_block_height_returns_error(t *testing.T) {
	store := mocks.NewMockChainStatusStore(t)
	deps := Deps{Logger: logger.Test(t), Store: store}
	cmds := InitCCVChainStatusesCommands(deps)
	setHeightCmd := findCmd(cmds, cmdNameSetFinalizedHeight)
	require.NotNil(t, setHeightCmd)
	app := cli.NewApp()
	app.Commands = []cli.Command{*setHeightCmd}
	err := app.Run([]string{"chainlink", cmdNameSetFinalizedHeight, "--chain-selector", "1", "--verifier-id", "v1"})
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
