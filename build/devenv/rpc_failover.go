package ccv

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const (
	defaultEVMRPCProxyImage = "nginx:alpine"
	evmRPCProxyPort         = "8545/tcp"
)

// EVMRPCFailoverCfg enables opt-in devenv infrastructure for exercising the
// standalone EVM multi-node client. Each EVM chain is exposed to standalone
// services through a primary and secondary proxy backed by the same chain.
// The secondary starts stopped so a test can deterministically prove that the
// services recover after their initially healthy primary disappears.
type EVMRPCFailoverCfg struct {
	Enabled bool                                  `toml:"enabled"`
	Image   string                                `toml:"image,omitempty"`
	Out     map[string]*EVMRPCFailoverChainOutput `toml:"out,omitempty"`
}

// EVMRPCFailoverChainOutput identifies the independently controllable proxy
// containers for one chain. PrimaryNode and SecondaryNode are mounted into
// standalone services; the direct chain endpoint remains first in the stored
// blockchain output so the E2E test driver is independent from the outage it
// creates.
type EVMRPCFailoverChainOutput struct {
	PrimaryContainerName   string           `toml:"primary_container_name"`
	SecondaryContainerName string           `toml:"secondary_container_name"`
	PrimaryNode            *blockchain.Node `toml:"primary_node"`
	SecondaryNode          *blockchain.Node `toml:"secondary_node"`

	directNodes []*blockchain.Node
}

type evmRPCProxyLauncher func(
	ctx context.Context,
	image string,
	containerName string,
	upstream *blockchain.Node,
	started bool,
) (*blockchain.Node, error)

func configureEVMRPCFailover(
	ctx context.Context,
	cfg *EVMRPCFailoverCfg,
	outputs []*blockchain.Output,
	launch evmRPCProxyLauncher,
) error {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	if launch == nil {
		return fmt.Errorf("EVM RPC failover proxy launcher is nil")
	}
	if cfg.Image == "" {
		cfg.Image = defaultEVMRPCProxyImage
	}
	cfg.Out = make(map[string]*EVMRPCFailoverChainOutput)

	for _, output := range outputs {
		if output == nil || output.Family != blockchain.FamilyEVM {
			continue
		}
		if len(output.Nodes) == 0 || output.Nodes[0] == nil {
			return fmt.Errorf("EVM chain %s has no direct RPC node to proxy", output.ChainID)
		}

		directNodes := append([]*blockchain.Node(nil), output.Nodes...)
		baseName := strings.TrimPrefix(output.ContainerName, "/")
		if baseName == "" {
			baseName = "evm-" + output.ChainID
		}
		primaryName := baseName + "-rpc-primary"
		secondaryName := baseName + "-rpc-secondary"

		primaryNode, err := launch(ctx, cfg.Image, primaryName, directNodes[0], true)
		if err != nil {
			return fmt.Errorf("launching primary RPC proxy for EVM chain %s: %w", output.ChainID, err)
		}
		secondaryNode, err := launch(ctx, cfg.Image, secondaryName, directNodes[0], false)
		if err != nil {
			return fmt.Errorf("creating secondary RPC proxy for EVM chain %s: %w", output.ChainID, err)
		}

		// Only the two proxies are visible while standalone service configs are
		// generated. The stopped secondary makes the primary deterministic.
		output.Nodes = []*blockchain.Node{primaryNode, secondaryNode}
		cfg.Out[output.ChainID] = &EVMRPCFailoverChainOutput{
			PrimaryContainerName:   primaryName,
			SecondaryContainerName: secondaryName,
			PrimaryNode:            primaryNode,
			SecondaryNode:          secondaryNode,
			directNodes:            directNodes,
		}
	}

	if len(cfg.Out) == 0 {
		return fmt.Errorf("EVM RPC failover is enabled but no EVM chains were configured")
	}
	return nil
}

// restoreDirectEVMRPCNodes is called only after all standalone containers have
// received their mounted configs. It makes test-side CLDF clients use the
// direct Anvil endpoint while retaining the proxies in the serialized output.
func restoreDirectEVMRPCNodes(cfg *EVMRPCFailoverCfg, outputs []*blockchain.Output) {
	if cfg == nil || !cfg.Enabled {
		return
	}
	for _, output := range outputs {
		if output == nil {
			continue
		}
		proxyOutput := cfg.Out[output.ChainID]
		if proxyOutput == nil || len(proxyOutput.directNodes) == 0 {
			continue
		}
		nodes := append([]*blockchain.Node(nil), proxyOutput.directNodes...)
		nodes = append(nodes, proxyOutput.PrimaryNode, proxyOutput.SecondaryNode)
		output.Nodes = nodes
	}
}

func launchEVMRPCProxy(
	ctx context.Context,
	image string,
	containerName string,
	upstream *blockchain.Node,
	started bool,
) (*blockchain.Node, error) {
	upstreamURL, hasWebSocket, err := validateEVMRPCProxyUpstream(upstream)
	if err != nil {
		return nil, err
	}

	configFile, err := os.CreateTemp("", "ccv-evm-rpc-proxy-*.conf")
	if err != nil {
		return nil, fmt.Errorf("creating nginx config: %w", err)
	}
	configPath := configFile.Name()
	defer func() { _ = os.Remove(configPath) }()
	if _, err := configFile.WriteString(evmRPCProxyNginxConfig(upstreamURL)); err != nil {
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
		ExposedPorts: []string{evmRPCProxyPort},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {containerName},
		},
		Files: []testcontainers.ContainerFile{{
			HostFilePath:      configPath,
			ContainerFilePath: "/etc/nginx/nginx.conf",
			FileMode:          0o644,
		}},
		WaitingFor: wait.ForListeningPort(evmRPCProxyPort).
			WithStartupTimeout(30 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          started,
	})
	if err != nil {
		return nil, fmt.Errorf("creating proxy container %s: %w", containerName, err)
	}

	port := strings.TrimSuffix(evmRPCProxyPort, "/tcp")
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
	mappedPort, err := container.MappedPort(ctx, evmRPCProxyPort)
	if err != nil {
		return nil, fmt.Errorf("getting proxy container port: %w", err)
	}
	node.ExternalHTTPUrl = fmt.Sprintf("http://%s:%s", host, mappedPort.Port())
	if hasWebSocket {
		node.ExternalWSUrl = fmt.Sprintf("ws://%s:%s", host, mappedPort.Port())
	}
	return node, nil
}

func validateEVMRPCProxyUpstream(node *blockchain.Node) (string, bool, error) {
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

	hasWebSocket := node.InternalWSUrl != ""
	if hasWebSocket {
		wsURL, err := url.Parse(node.InternalWSUrl)
		if err != nil {
			return "", false, fmt.Errorf("parsing direct node WebSocket URL: %w", err)
		}
		wsScheme := map[string]string{"ws": "http", "wss": "https"}[wsURL.Scheme]
		if wsScheme == "" || wsScheme != httpURL.Scheme || wsURL.Host != httpURL.Host ||
			(wsURL.Path != "" && wsURL.Path != "/") || wsURL.RawQuery != "" || wsURL.Fragment != "" {
			return "", false, fmt.Errorf("EVM RPC failover proxies require HTTP and WebSocket URLs on the same endpoint")
		}
	}

	return fmt.Sprintf("%s://%s", httpURL.Scheme, httpURL.Host), hasWebSocket, nil
}

func evmRPCProxyNginxConfig(upstreamURL string) string {
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
