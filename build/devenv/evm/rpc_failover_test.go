package evm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

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
	cfg := &RPCFailoverInput{Enabled: true}

	type launchCall struct {
		name    string
		started bool
	}
	var calls []launchCall
	launcher := func(
		_ context.Context,
		_ string,
		name string,
		_ *blockchain.Node,
		started bool,
	) (*blockchain.Node, error) {
		calls = append(calls, launchCall{name: name, started: started})
		return &blockchain.Node{InternalHTTPUrl: "http://" + name + ":8545"}, nil
	}

	failoverOutput, finalize, err := configureRPCFailover(t.Context(), cfg, []*blockchain.Output{output}, launcher)
	require.NoError(t, err)
	require.Equal(t, defaultRPCProxyImage, failoverOutput.Image)
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

func TestValidateRPCProxyUpstream(t *testing.T) {
	t.Parallel()

	upstream, hasWebSocket, err := validateRPCProxyUpstream(&blockchain.Node{
		InternalHTTPUrl: "http://blockchain-src:8545",
		InternalWSUrl:   "ws://blockchain-src:8545",
	})
	require.NoError(t, err)
	require.Equal(t, "http://blockchain-src:8545", upstream)
	require.True(t, hasWebSocket)

	_, _, err = validateRPCProxyUpstream(&blockchain.Node{
		InternalHTTPUrl: "http://blockchain-src:8545",
		InternalWSUrl:   "ws://blockchain-src:8546",
	})
	require.ErrorContains(t, err, "same endpoint")

	nginxConfig := rpcProxyNginxConfig(upstream)
	require.Contains(t, nginxConfig, "proxy_pass http://blockchain-src:8545;")
	require.Contains(t, nginxConfig, "proxy_set_header Upgrade $http_upgrade;")
}

func TestLocalNetworkOutputRoundTripsThroughOpaqueConfig(t *testing.T) {
	t.Parallel()

	want := LocalNetworkOutput{
		RPCFailover: &RPCFailoverOutput{
			Image: defaultRPCProxyImage,
			Chains: map[string]*RPCFailoverChainOutput{
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
	got, err := util.OpaqueToConcreteStrict[LocalNetworkOutput](opaque)
	require.NoError(t, err)
	require.Equal(t, want, *got)
}
