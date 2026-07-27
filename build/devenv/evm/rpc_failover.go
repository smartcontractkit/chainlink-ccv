package evm

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const (
	defaultRPCProxyImage = "nginx:alpine"
	rpcProxyPort         = "8545/tcp"
)

// LocalNetworkInput is the EVM-owned schema for optional local-network
// extensions. The chain-agnostic environment stores this as opaque input.
type LocalNetworkInput struct {
	RPCFailover *RPCFailoverInput `toml:"rpc_failover,omitempty"`
}

// LocalNetworkOutput is the EVM-owned output schema for local-network
// extensions. Tests decode it from the chain-agnostic environment output.
type LocalNetworkOutput struct {
	RPCFailover *RPCFailoverOutput `toml:"rpc_failover,omitempty"`
}

// RPCFailoverInput enables opt-in infrastructure for exercising the
// standalone EVM multi-node client.
type RPCFailoverInput struct {
	Enabled bool   `toml:"enabled"`
	Image   string `toml:"image,omitempty"`
}

// RPCFailoverOutput describes the proxy image and independently controllable
// proxy containers created for each EVM chain.
type RPCFailoverOutput struct {
	Image  string                             `toml:"image"`
	Chains map[string]*RPCFailoverChainOutput `toml:"chains"`
}

// RPCFailoverChainOutput identifies the primary and secondary proxies for one
// chain. Standalone services receive these nodes while the direct endpoint is
// restored in the serialized blockchain output for test-side clients.
type RPCFailoverChainOutput struct {
	PrimaryContainerName   string           `toml:"primary_container_name"`
	SecondaryContainerName string           `toml:"secondary_container_name"`
	PrimaryNode            *blockchain.Node `toml:"primary_node"`
	SecondaryNode          *blockchain.Node `toml:"secondary_node"`
}

type rpcProxyLauncher func(
	ctx context.Context,
	image string,
	containerName string,
	upstream *blockchain.Node,
	started bool,
) (*blockchain.Node, error)

// ConfigureLocalNetworks implements chainreg.LocalNetworkConfigurator for EVM.
func ConfigureLocalNetworks(
	ctx context.Context,
	input util.OpaqueConfig,
	outputs []*blockchain.Output,
) (util.OpaqueConfig, chainreg.LocalNetworkFinalizer, error) {
	cfg, err := util.OpaqueToConcreteStrict[LocalNetworkInput](input)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding EVM local network config: %w", err)
	}
	if cfg.RPCFailover == nil || !cfg.RPCFailover.Enabled {
		return nil, nil, nil
	}

	failoverOutput, finalize, err := configureRPCFailover(ctx, cfg.RPCFailover, outputs, launchRPCProxy)
	if err != nil {
		return nil, nil, err
	}
	opaqueOutput, err := util.ConcreteToOpaque(LocalNetworkOutput{RPCFailover: failoverOutput})
	if err != nil {
		finalize()
		return nil, nil, fmt.Errorf("encoding EVM local network output: %w", err)
	}
	return opaqueOutput, finalize, nil
}

func configureRPCFailover(
	ctx context.Context,
	cfg *RPCFailoverInput,
	outputs []*blockchain.Output,
	launch rpcProxyLauncher,
) (*RPCFailoverOutput, chainreg.LocalNetworkFinalizer, error) {
	if launch == nil {
		return nil, nil, fmt.Errorf("EVM RPC failover proxy launcher is nil")
	}
	image := cfg.Image
	if image == "" {
		image = defaultRPCProxyImage
	}

	result := &RPCFailoverOutput{
		Image:  image,
		Chains: make(map[string]*RPCFailoverChainOutput),
	}
	directNodes := make(map[string][]*blockchain.Node)
	finalize := func() {
		restoreDirectRPCNodes(outputs, directNodes, result.Chains)
	}

	for _, output := range outputs {
		if output == nil || output.Family != blockchain.FamilyEVM {
			continue
		}
		if len(output.Nodes) == 0 || output.Nodes[0] == nil {
			finalize()
			return nil, nil, fmt.Errorf("EVM chain %s has no direct RPC node to proxy", output.ChainID)
		}

		nodes := append([]*blockchain.Node(nil), output.Nodes...)
		baseName := strings.TrimPrefix(output.ContainerName, "/")
		if baseName == "" {
			baseName = "evm-" + output.ChainID
		}
		primaryName := baseName + "-rpc-primary"
		secondaryName := baseName + "-rpc-secondary"

		primaryNode, err := launch(ctx, image, primaryName, nodes[0], true)
		if err != nil {
			finalize()
			return nil, nil, fmt.Errorf("launching primary RPC proxy for EVM chain %s: %w", output.ChainID, err)
		}
		secondaryNode, err := launch(ctx, image, secondaryName, nodes[0], false)
		if err != nil {
			finalize()
			return nil, nil, fmt.Errorf("creating secondary RPC proxy for EVM chain %s: %w", output.ChainID, err)
		}

		// Only the proxies are visible while standalone service configs are
		// generated. The stopped secondary makes the primary deterministic.
		directNodes[output.ChainID] = nodes
		output.Nodes = []*blockchain.Node{primaryNode, secondaryNode}
		result.Chains[output.ChainID] = &RPCFailoverChainOutput{
			PrimaryContainerName:   primaryName,
			SecondaryContainerName: secondaryName,
			PrimaryNode:            primaryNode,
			SecondaryNode:          secondaryNode,
		}
	}

	if len(result.Chains) == 0 {
		return nil, nil, fmt.Errorf("EVM RPC failover is enabled but no EVM chains were configured")
	}
	return result, finalize, nil
}

func restoreDirectRPCNodes(
	outputs []*blockchain.Output,
	directNodes map[string][]*blockchain.Node,
	proxyOutputs map[string]*RPCFailoverChainOutput,
) {
	for _, output := range outputs {
		if output == nil || len(directNodes[output.ChainID]) == 0 {
			continue
		}
		proxyOutput := proxyOutputs[output.ChainID]
		if proxyOutput == nil {
			continue
		}
		nodes := append([]*blockchain.Node(nil), directNodes[output.ChainID]...)
		nodes = append(nodes, proxyOutput.PrimaryNode, proxyOutput.SecondaryNode)
		output.Nodes = nodes
	}
}

func launchRPCProxy(
	ctx context.Context,
	image string,
	containerName string,
	upstream *blockchain.Node,
	started bool,
) (*blockchain.Node, error) {
	upstreamURL, hasWebSocket, err := validateRPCProxyUpstream(upstream)
	if err != nil {
		return nil, err
	}

	configFile, err := os.CreateTemp("", "ccv-evm-rpc-proxy-*.conf")
	if err != nil {
		return nil, fmt.Errorf("creating nginx config: %w", err)
	}
	configPath := configFile.Name()
	defer func() { _ = os.Remove(configPath) }()
	if _, err := configFile.WriteString(rpcProxyNginxConfig(upstreamURL)); err != nil {
		_ = configFile.Close()
		return nil, fmt.Errorf("writing nginx config: %w", err)
	}
	if err := configFile.Close(); err != nil {
		return nil, fmt.Errorf("closing nginx config: %w", err)
	}

	req := testcontainers.ContainerRequest{
		Image:        image,
		Name:         containerName,
		Labels:       framework.DefaultTCLabels(),
		Networks:     []string{framework.DefaultNetworkName},
		ExposedPorts: []string{rpcProxyPort},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {containerName},
		},
		Files: []testcontainers.ContainerFile{{
			HostFilePath:      configPath,
			ContainerFilePath: "/etc/nginx/nginx.conf",
			FileMode:          0o644,
		}},
		WaitingFor: wait.ForListeningPort(rpcProxyPort).
			WithStartupTimeout(30 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          started,
	})
	if err != nil {
		return nil, fmt.Errorf("creating proxy container %s: %w", containerName, err)
	}

	port := strings.TrimSuffix(rpcProxyPort, "/tcp")
	node := &blockchain.Node{
		InternalHTTPUrl: fmt.Sprintf("http://%s:%s", containerName, port),
	}
	if hasWebSocket {
		node.InternalWSUrl = fmt.Sprintf("ws://%s:%s", containerName, port)
	}
	if !started {
		return node, nil
	}

	host, err := framework.GetHostWithContext(ctx, container)
	if err != nil {
		return nil, fmt.Errorf("getting proxy container host: %w", err)
	}
	mappedPort, err := container.MappedPort(ctx, rpcProxyPort)
	if err != nil {
		return nil, fmt.Errorf("getting proxy container port: %w", err)
	}
	node.ExternalHTTPUrl = fmt.Sprintf("http://%s:%s", host, mappedPort.Port())
	if hasWebSocket {
		node.ExternalWSUrl = fmt.Sprintf("ws://%s:%s", host, mappedPort.Port())
	}
	return node, nil
}

func validateRPCProxyUpstream(node *blockchain.Node) (string, bool, error) {
	if node == nil || node.InternalHTTPUrl == "" {
		return "", false, fmt.Errorf("direct node has no internal HTTP URL")
	}
	httpURL, err := url.Parse(node.InternalHTTPUrl)
	if err != nil {
		return "", false, fmt.Errorf("parsing direct node HTTP URL: %w", err)
	}
	if (httpURL.Scheme != "http" && httpURL.Scheme != "https") || httpURL.Host == "" {
		return "", false, fmt.Errorf("unsupported direct node HTTP URL %q", node.InternalHTTPUrl)
	}
	if httpURL.User != nil || httpURL.RawQuery != "" || httpURL.Fragment != "" || (httpURL.Path != "" && httpURL.Path != "/") {
		return "", false, fmt.Errorf("EVM RPC failover proxies require a host-only internal URL, got %q", node.InternalHTTPUrl)
	}

	upstreamURL := fmt.Sprintf("%s://%s", httpURL.Scheme, httpURL.Host)
	if node.InternalWSUrl == "" {
		return upstreamURL, false, nil
	}

	wsURL, err := url.Parse(node.InternalWSUrl)
	if err != nil {
		return "", false, fmt.Errorf("parsing direct node WebSocket URL: %w", err)
	}
	wsScheme := map[string]string{"ws": "http", "wss": "https"}[wsURL.Scheme]
	if wsScheme == "" || wsURL.Host == "" || wsURL.User != nil ||
		(wsURL.Path != "" && wsURL.Path != "/") || wsURL.RawQuery != "" || wsURL.Fragment != "" {
		return "", false, fmt.Errorf("unsupported direct node WebSocket URL %q", node.InternalWSUrl)
	}
	// A single proxy endpoint can preserve WebSocket support only when both
	// protocols share an upstream. Otherwise clients use HTTP polling.
	if wsScheme != httpURL.Scheme || wsURL.Host != httpURL.Host {
		return upstreamURL, false, nil
	}

	return upstreamURL, true, nil
}

func rpcProxyNginxConfig(upstreamURL string) string {
	return fmt.Sprintf(`
worker_processes auto;
error_log /dev/stderr warn;
pid /tmp/nginx.pid;

events {}

http {
    map $http_upgrade $connection_upgrade {
        default upgrade;
        '' close;
    }

    access_log /dev/stdout combined;

    server {
        listen 8545;

        location / {
            proxy_pass %s;
            proxy_http_version 1.1;
            proxy_set_header Host $proxy_host;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_read_timeout 1h;
            proxy_send_timeout 1h;
        }
    }
}
`, upstreamURL)
}
