package e2e

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

const (
	verifierBinary       = "/app/cmd/verifier/committee/tmp/committee"
	committeeProcessMatch = "tmp/committee"
)

func execInContainer(containerName string, args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"exec", containerName}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func parseFirstListRow(listOutput string) (chainSelector string, ok bool) {
	if strings.Contains(listOutput, "No chain status rows found.") {
		return "", false
	}
	lines := strings.Split(listOutput, "\n")
	for _, line := range lines {
		if !strings.Contains(line, "|") {
			continue
		}
		parts := strings.Split(line, "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) < 2 {
			continue
		}
		if strings.Contains(parts[0], "Chain") && strings.Contains(line, "verifier_id") {
			continue
		}
		if strings.TrimLeft(line, "-+| \t") == "" {
			continue
		}
		sel := parts[1]
		if _, err := strconv.ParseUint(sel, 10, 64); err != nil {
			continue
		}
		return sel, true
	}
	return "", false
}

func TestE2ESmoke_ChainStatusesCLI(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(in.Verifier), 1, "expected at least one verifier in the environment")
	require.NotNil(t, in.Verifier[0].Out, "first verifier must have output (container name)")
	containerName := strings.TrimPrefix(in.Verifier[0].Out.ContainerName, "/")
	require.NotEmpty(t, containerName, "verifier container name must be set")
	verifierID := in.Verifier[0].Out.VerifierID
	require.NotEmpty(t, verifierID, "verifier ID must be set")

	cliArgs := func(subcommand string, extra ...string) []string {
		return append([]string{verifierBinary, "ccv", "chain-statuses", subcommand}, extra...)
	}

	t.Cleanup(func() {
		_, _ = execInContainer(containerName, "pkill", "-CONT", "-f", committeeProcessMatch)
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	listOutput, err := execInContainer(containerName, cliArgs("list")...)
	require.NoError(t, err, "list should succeed: %s", listOutput)
	require.Contains(t, listOutput, "Chain", "output must contain Chain header; got: %s", listOutput)
	require.Contains(t, listOutput, "Chain Selector", "output must contain Chain Selector header; got: %s", listOutput)

	chainSelector, hasRow := parseFirstListRow(listOutput)
	require.True(t, hasRow, "list output must contain at least one chain status row to exercise disable/enable/set-finalized-height; got: %s", listOutput)

	_, err = execInContainer(containerName, "pkill", "-STOP", "-f", committeeProcessMatch)
	require.NoError(t, err, "must be able to stop verifier process (pkill -STOP) before running CLI mutations")

	_, err = execInContainer(containerName, cliArgs("disable", "--chain-selector", chainSelector, "--verifier-id", verifierID)...)
	require.NoError(t, err, "disable should succeed")

	_, err = execInContainer(containerName, cliArgs("set-finalized-height", "--chain-selector", chainSelector, "--verifier-id", verifierID, "--block-height", "1")...)
	require.NoError(t, err, "set-finalized-height should succeed")

	_, err = execInContainer(containerName, cliArgs("enable", "--chain-selector", chainSelector, "--verifier-id", verifierID)...)
	require.NoError(t, err, "enable should succeed")

	finalList, err := execInContainer(containerName, cliArgs("list")...)
	require.NoError(t, err, "final list should succeed: %s", finalList)
	require.Contains(t, finalList, chainSelector, "final list should contain chain selector %s; got: %s", chainSelector, finalList)
}
