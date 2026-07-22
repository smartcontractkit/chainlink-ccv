package chaos

import (
	"fmt"
	"testing"
	"time"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
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

func TestBuildNetemDelayCommand(t *testing.T) {
	t.Parallel()

	duration := 1 * time.Minute

	t.Run("single target", func(t *testing.T) {
		t.Parallel()
		cmd := BuildNetemDelayCommand(duration, 400, []string{"blockchain-src"})
		require.Equal(t,
			"netem --tc-image=ghcr.io/alexei-led/pumba-debian-nettools --duration=1m0s delay --time=400 re2:^blockchain-src$",
			cmd)
	})

	t.Run("multiple targets", func(t *testing.T) {
		t.Parallel()
		cmd := BuildNetemDelayCommand(duration, 1000, []string{"blockchain-src", "blockchain-dst"})
		require.Equal(t,
			"netem --tc-image=ghcr.io/alexei-led/pumba-debian-nettools --duration=1m0s delay --time=1000 re2:(^blockchain-src$|^blockchain-dst$)",
			cmd)
	})
}

func TestBlockchainContainer(t *testing.T) {
	t.Parallel()

	t.Run("prefers Out.ContainerName", func(t *testing.T) {
		t.Parallel()
		cfg := &ccv.Cfg{
			Blockchains: []*blockchain.Input{
				{ContainerName: "blockchain-src", Out: &blockchain.Output{ContainerName: "/blockchain-src"}},
				{ContainerName: "blockchain-dst", Out: &blockchain.Output{ContainerName: "/blockchain-dst"}},
			},
		}
		name, err := BlockchainContainer(cfg, 1)
		require.NoError(t, err)
		require.Equal(t, "blockchain-dst", name)
	})

	t.Run("falls back to Input.ContainerName when Out is nil", func(t *testing.T) {
		t.Parallel()
		cfg := &ccv.Cfg{
			Blockchains: []*blockchain.Input{
				{ContainerName: "blockchain-src"},
			},
		}
		name, err := BlockchainContainer(cfg, 0)
		require.NoError(t, err)
		require.Equal(t, "blockchain-src", name)
	})

	t.Run("index out of range", func(t *testing.T) {
		t.Parallel()
		cfg := &ccv.Cfg{
			Blockchains: []*blockchain.Input{{ContainerName: "blockchain-src"}},
		}
		_, err := BlockchainContainer(cfg, 5)
		require.Error(t, err)
	})
}

func TestBlockchainContainerForSelector(t *testing.T) {
	t.Parallel()

	details, err := chain_selectors.GetChainDetailsByChainIDAndFamily("2337", "evm")
	require.NoError(t, err)
	dstSelector := details.ChainSelector

	cfg := &ccv.Cfg{
		Blockchains: []*blockchain.Input{
			{
				ContainerName: "blockchain-src",
				Out: &blockchain.Output{
					ChainID:       "1337",
					Family:        "evm",
					ContainerName: "/blockchain-src",
				},
			},
			{
				ContainerName: "blockchain-dst",
				Out: &blockchain.Output{
					ChainID:       "2337",
					Family:        "evm",
					ContainerName: "/blockchain-dst",
				},
			},
		},
	}

	name, err := BlockchainContainerForSelector(cfg, dstSelector)
	require.NoError(t, err)
	require.Equal(t, "blockchain-dst", name)

	_, err = BlockchainContainerForSelector(cfg, 999999)
	require.Error(t, err)
}
