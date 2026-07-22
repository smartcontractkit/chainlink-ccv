package ccv

import (
	"context"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

func TestConfigureEVMRPCFailoverUsesPrimaryAndInitiallyStoppedSecondary(t *testing.T) {
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
	cfg := &EVMRPCFailoverCfg{Enabled: true}

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

	require.NoError(t, configureEVMRPCFailover(t.Context(), cfg, []*blockchain.Output{output}, launcher))
	require.Equal(t, defaultEVMRPCProxyImage, cfg.Image)
	require.Equal(t, []launchCall{
		{name: "blockchain-src-rpc-primary", started: true},
		{name: "blockchain-src-rpc-secondary", started: false},
	}, calls)
	require.Len(t, output.Nodes, 2)
	require.Same(t, cfg.Out["1337"].PrimaryNode, output.Nodes[0])
	require.Same(t, cfg.Out["1337"].SecondaryNode, output.Nodes[1])

	restoreDirectEVMRPCNodes(cfg, []*blockchain.Output{output})
	require.Len(t, output.Nodes, 3)
	require.Same(t, directNode, output.Nodes[0])
	require.Same(t, cfg.Out["1337"].PrimaryNode, output.Nodes[1])
	require.Same(t, cfg.Out["1337"].SecondaryNode, output.Nodes[2])
}

func TestValidateEVMRPCProxyUpstream(t *testing.T) {
	t.Parallel()

	upstream, hasWebSocket, err := validateEVMRPCProxyUpstream(&blockchain.Node{
		InternalHTTPUrl: "http://blockchain-src:8545",
		InternalWSUrl:   "ws://blockchain-src:8545",
	})
	require.NoError(t, err)
	require.Equal(t, "http://blockchain-src:8545", upstream)
	require.True(t, hasWebSocket)

	_, _, err = validateEVMRPCProxyUpstream(&blockchain.Node{
		InternalHTTPUrl: "http://blockchain-src:8545",
		InternalWSUrl:   "ws://blockchain-src:8546",
	})
	require.ErrorContains(t, err, "same endpoint")

	nginxConfig := evmRPCProxyNginxConfig(upstream)
	require.Contains(t, nginxConfig, "proxy_pass http://blockchain-src:8545;")
	require.Contains(t, nginxConfig, "proxy_set_header Upgrade $http_upgrade;")
}

func TestEVMRPCFailoverOutputRoundTripsThroughTOML(t *testing.T) {
	t.Parallel()

	cfg := EVMRPCFailoverCfg{
		Enabled: true,
		Image:   defaultEVMRPCProxyImage,
		Out: map[string]*EVMRPCFailoverChainOutput{
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
	}

	data, err := toml.Marshal(cfg)
	require.NoError(t, err)
	var decoded EVMRPCFailoverCfg
	require.NoError(t, toml.Unmarshal(data, &decoded))
	require.Equal(t, cfg.Enabled, decoded.Enabled)
	require.Equal(t, cfg.Image, decoded.Image)
	require.Equal(t, cfg.Out["1337"].PrimaryContainerName, decoded.Out["1337"].PrimaryContainerName)
	require.Equal(t, cfg.Out["1337"].SecondaryNode.InternalHTTPUrl, decoded.Out["1337"].SecondaryNode.InternalHTTPUrl)
}

func TestEVMRPCFailoverOverlayLoadsWithStandardConfig(t *testing.T) {
	t.Parallel()

	cfg, err := Load[Cfg]([]string{"env.toml", "env-rpc-failover.toml"})
	require.NoError(t, err)
	require.NotNil(t, cfg.EVMRPCFailover)
	require.True(t, cfg.EVMRPCFailover.Enabled)
}
