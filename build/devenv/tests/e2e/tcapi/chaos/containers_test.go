package chaos

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
)

func TestBuildStopCommand(t *testing.T) {
	t.Parallel()

	duration := 20 * time.Second

	t.Run("single target aggregator", func(t *testing.T) {
		t.Parallel()
		cmd := BuildStopCommand(duration, []string{"default-aggregator-nginx"})
		require.Equal(t, "stop --duration=20s --restart re2:^default-aggregator-nginx$", cmd)
	})

	t.Run("single target indexer", func(t *testing.T) {
		t.Parallel()
		cmd := BuildStopCommand(duration, []string{"indexer-1"})
		require.Equal(t, "stop --duration=20s --restart re2:^indexer-1$", cmd)
	})

	t.Run("multiple targets", func(t *testing.T) {
		t.Parallel()
		cmd := BuildStopCommand(duration, []string{"exec-1", "exec-2"})
		require.Equal(t, "stop --duration=20s --restart re2:(^exec-1$|^exec-2$)", cmd)
	})
}

func TestDefaultAggregatorNginx(t *testing.T) {
	t.Parallel()

	cfg := &ccv.Cfg{
		Aggregator: []*services.AggregatorInput{
			{
				CommitteeName: "default",
				Out:           &services.AggregatorOutput{NginxContainerName: "/default-aggregator-nginx"},
			},
		},
	}

	name, err := DefaultAggregatorNginx(cfg, "default")
	require.NoError(t, err)
	require.Equal(t, "default-aggregator-nginx", name)
}

func TestExecutorContainersForDest(t *testing.T) {
	t.Parallel()

	evmDest := uint64(3379446385462418246)
	solDest := uint64(12463857294658392847)

	cfg := &ccv.Cfg{
		EnvironmentTopology: &ccvdeployment.EnvironmentTopology{
			ExecutorPools: map[string]ccvdeployment.ExecutorPoolConfig{
				"default": {
					ChainConfigs: map[string]ccvdeployment.ChainExecutorPoolConfig{
						fmt.Sprintf("%d", evmDest): {NOPAliases: []string{"default-executor-1"}},
						fmt.Sprintf("%d", solDest): {NOPAliases: []string{"solana-executor-1"}},
					},
				},
			},
		},
		Executor: []*executor.Input{
			{
				NOPAlias:          "default-executor-1",
				ExecutorQualifier: "default",
				Out:               &executor.Output{ContainerName: "/default-executor-1"},
			},
			{
				NOPAlias:          "solana-executor-1",
				ExecutorQualifier: "default",
				Out:               &executor.Output{ContainerName: "/solana-solana-executor-1"},
			},
		},
	}

	evmExecs, err := ExecutorContainersForDest(cfg, evmDest, "default")
	require.NoError(t, err)
	require.Equal(t, []string{"default-executor-1"}, evmExecs)

	solExecs, err := ExecutorContainersForDest(cfg, solDest, "default")
	require.NoError(t, err)
	require.Equal(t, []string{"solana-solana-executor-1"}, solExecs)
}

func TestVerifierContainersWithFilter(t *testing.T) {
	t.Parallel()

	cfg := &ccv.Cfg{
		Verifier: []*committeeverifier.Input{
			{
				CommitteeName: "default",
				ContainerName: "verifier-1",
				Out:           &committeeverifier.Output{ContainerName: "/verifier-1"},
			},
			{
				CommitteeName: "default",
				ContainerName: "verifier-2",
				Out:           &committeeverifier.Output{ContainerName: "/verifier-2"},
			},
		},
	}

	names, err := VerifierContainers(cfg, "default", func(v *committeeverifier.Input) bool {
		return v.ContainerName == "verifier-1"
	})
	require.NoError(t, err)
	require.Equal(t, []string{"verifier-1"}, names)
}
