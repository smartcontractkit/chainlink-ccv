package localnetwork

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

type launchCall struct {
	name    string
	started bool
}

// recordingLauncher stands in for the docker launch so the topology logic can
// be tested without containers.
func recordingLauncher(calls *[]launchCall) proxyLauncher {
	return func(
		_ context.Context,
		_ string,
		name string,
		_ *blockchain.Node,
		started bool,
	) (*blockchain.Node, error) {
		*calls = append(*calls, launchCall{name: name, started: started})
		return &blockchain.Node{InternalHTTPUrl: "http://" + name + ":8545"}, nil
	}
}

func TestConfigureRPCFailoverUsesPrimaryAndInitiallyStoppedSecondary(t *testing.T) {
	t.Parallel()

	directNode := &blockchain.Node{
		ExternalHTTPUrl: "http://localhost:8545",
		InternalHTTPUrl: "http://blockchain-src:8545",
		ExternalWSUrl:   "ws://localhost:8545",
		InternalWSUrl:   "ws://blockchain-src:8545",
	}
	output := &blockchain.Output{
		Family:        blockchain.FamilyEVM,
		ChainID:       "1337",
		ContainerName: "blockchain-src",
		Nodes:         []*blockchain.Node{directNode},
	}

	var calls []launchCall
	failoverOutput, finalize, err := configureRPCFailover(
		t.Context(), blockchain.FamilyEVM, &FailoverInput{Enabled: true},
		[]*blockchain.Output{output}, recordingLauncher(&calls),
	)
	require.NoError(t, err)
	require.Equal(t, DefaultProxyImage, failoverOutput.Image)
	require.Equal(t, []launchCall{
		{name: "blockchain-src-rpc-primary", started: true},
		{name: "blockchain-src-rpc-secondary", started: false},
	}, calls)
	require.Len(t, output.Nodes, 2)
	require.Same(t, failoverOutput.Chains["1337"].PrimaryNode, output.Nodes[0])
	require.Same(t, failoverOutput.Chains["1337"].SecondaryNode, output.Nodes[1])

	finalize()
	require.Len(t, output.Nodes, 3)
	require.Same(t, directNode, output.Nodes[0])
	require.Same(t, failoverOutput.Chains["1337"].PrimaryNode, output.Nodes[1])
	require.Same(t, failoverOutput.Chains["1337"].SecondaryNode, output.Nodes[2])
}

func TestConfigureRPCFailoverIgnoresOtherFamilies(t *testing.T) {
	t.Parallel()

	solana := &blockchain.Output{
		Family:        blockchain.FamilySolana,
		ChainID:       "sol-devnet",
		ContainerName: "blockchain-solana-1",
		Nodes:         []*blockchain.Node{{InternalHTTPUrl: "http://blockchain-solana-1:8899"}},
	}
	evm := &blockchain.Output{
		Family:        blockchain.FamilyEVM,
		ChainID:       "1337",
		ContainerName: "blockchain-src",
		// No nodes: an EVM chain in this state would fail, proving the EVM
		// chain is never looked at when Solana is the configured family.
	}

	var calls []launchCall
	failoverOutput, _, err := configureRPCFailover(
		t.Context(), blockchain.FamilySolana, &FailoverInput{Enabled: true},
		[]*blockchain.Output{solana, evm}, recordingLauncher(&calls),
	)
	require.NoError(t, err)
	require.Equal(t, []launchCall{
		{name: "blockchain-solana-1-rpc-primary", started: true},
		{name: "blockchain-solana-1-rpc-secondary", started: false},
	}, calls)
	require.Len(t, failoverOutput.Chains, 1)
	require.Contains(t, failoverOutput.Chains, "sol-devnet")
}

func TestConfigureRPCFailoverRequiresAtLeastOneChain(t *testing.T) {
	t.Parallel()

	var calls []launchCall
	_, _, err := configureRPCFailover(
		t.Context(), blockchain.FamilySolana, &FailoverInput{Enabled: true},
		[]*blockchain.Output{{Family: blockchain.FamilyEVM, ChainID: "1337"}}, recordingLauncher(&calls),
	)
	require.ErrorContains(t, err, "no solana chains were configured")
	require.Empty(t, calls)
}

func TestPlanProxySharedHTTPAndWebSocketPort(t *testing.T) {
	t.Parallel()

	plan, err := planProxy(&blockchain.Node{
		InternalHTTPUrl: "http://blockchain-src:8545",
		InternalWSUrl:   "ws://blockchain-src:8545",
	})
	require.NoError(t, err)
	require.Equal(t, "8545", plan.httpPort)
	require.Equal(t, "8545", plan.wsPort)
	require.Equal(t, []listener{{port: "8545", upstream: "http://blockchain-src:8545"}}, plan.listeners)

	config := nginxConfig(plan.listeners)
	require.Contains(t, config, "listen 8545;")
	require.Contains(t, config, "proxy_pass http://blockchain-src:8545;")
	require.Contains(t, config, "proxy_set_header Upgrade $http_upgrade;")
}

// Solana serves RPC and WebSocket on adjacent ports. The proxy has to mirror
// both, or the log poller loses its subscriptions the moment it is proxied.
func TestPlanProxySplitHTTPAndWebSocketPorts(t *testing.T) {
	t.Parallel()

	plan, err := planProxy(&blockchain.Node{
		InternalHTTPUrl: "http://blockchain-solana-1:8899",
		InternalWSUrl:   "ws://blockchain-solana-1:8900",
	})
	require.NoError(t, err)
	require.Equal(t, "8899", plan.httpPort)
	require.Equal(t, "8900", plan.wsPort)
	require.Equal(t, []listener{
		{port: "8899", upstream: "http://blockchain-solana-1:8899"},
		{port: "8900", upstream: "http://blockchain-solana-1:8900"},
	}, plan.listeners)

	config := nginxConfig(plan.listeners)
	require.Contains(t, config, "listen 8899;")
	require.Contains(t, config, "proxy_pass http://blockchain-solana-1:8899;")
	require.Contains(t, config, "listen 8900;")
	require.Contains(t, config, "proxy_pass http://blockchain-solana-1:8900;")
}

func TestPlanProxyHTTPOnlyNode(t *testing.T) {
	t.Parallel()

	plan, err := planProxy(&blockchain.Node{InternalHTTPUrl: "http://blockchain-src:8545"})
	require.NoError(t, err)
	require.Equal(t, "8545", plan.httpPort)
	require.Empty(t, plan.wsPort)
	require.Len(t, plan.listeners, 1)
}

func TestPlanProxyRejectsUnusableUpstreams(t *testing.T) {
	t.Parallel()

	for name, node := range map[string]*blockchain.Node{
		"no internal HTTP URL": {ExternalHTTPUrl: "http://localhost:8545"},
		"no explicit port":     {InternalHTTPUrl: "http://blockchain-src"},
		"path":                 {InternalHTTPUrl: "http://blockchain-src:8545/rpc"},
		"query":                {InternalHTTPUrl: "http://blockchain-src:8545?key=abc"},
		"unsupported scheme":   {InternalHTTPUrl: "tcp://blockchain-src:8545"},
		"bad WebSocket scheme": {
			InternalHTTPUrl: "http://blockchain-src:8545",
			InternalWSUrl:   "http://blockchain-src:8546",
		},
		"same port, different host": {
			InternalHTTPUrl: "http://blockchain-src:8545",
			InternalWSUrl:   "ws://blockchain-other:8545",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := planProxy(node)
			require.Error(t, err)
		})
	}
}

func TestOutputRoundTripsThroughOpaqueConfig(t *testing.T) {
	t.Parallel()

	want := Output{
		RPCFailover: &FailoverOutput{
			Image: DefaultProxyImage,
			Chains: map[string]*FailoverChainOutput{
				"1337": {
					PrimaryContainerName:   "blockchain-src-rpc-primary",
					SecondaryContainerName: "blockchain-src-rpc-secondary",
					PrimaryNode: &blockchain.Node{
						InternalHTTPUrl: "http://blockchain-src-rpc-primary:8545",
					},
					SecondaryNode: &blockchain.Node{
						InternalHTTPUrl: "http://blockchain-src-rpc-secondary:8545",
					},
				},
			},
		},
	}

	opaque, err := util.ConcreteToOpaque(want)
	require.NoError(t, err)
	got, err := util.OpaqueToConcreteStrict[Output](opaque)
	require.NoError(t, err)
	require.Equal(t, want, *got)
}

func TestConfigureIsANoOpWhenFailoverIsDisabled(t *testing.T) {
	t.Parallel()

	input, err := util.ConcreteToOpaque(Input{RPCFailover: &FailoverInput{Enabled: false}})
	require.NoError(t, err)

	output, finalize, err := Configure(t.Context(), blockchain.FamilyEVM, input, nil)
	require.NoError(t, err)
	require.Nil(t, output)
	require.Nil(t, finalize)
}
