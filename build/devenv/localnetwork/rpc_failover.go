package localnetwork

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
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const (
	// DefaultProxyImage backs the failover proxies when the config names no image.
	DefaultProxyImage = "nginx:alpine"

	// PrimarySuffix and SecondarySuffix are appended to a chain's container name
	// to derive its proxy container names.
	PrimarySuffix   = "-rpc-primary"
	SecondarySuffix = "-rpc-secondary"

	proxyStartupTimeout = 30 * time.Second
	proxyConfigPath     = "/etc/nginx/nginx.conf"
)

// FailoverInput enables the RPC failover proxies for one chain family.
type FailoverInput struct {
	Enabled bool `toml:"enabled"`
	// Image is the reverse proxy image. It must accept an nginx.conf at
	// /etc/nginx/nginx.conf; leave it empty to use DefaultProxyImage.
	Image string `toml:"image,omitempty"`
}

// FailoverOutput describes the proxy image and the independently controllable
// proxy containers created for each chain of one family, keyed by chain ID.
type FailoverOutput struct {
	Image  string                          `toml:"image"`
	Chains map[string]*FailoverChainOutput `toml:"chains"`
}

// FailoverChainOutput identifies the primary and secondary proxies for one
// chain. Standalone services receive both nodes; the direct endpoint stays in
// the serialized blockchain output so test-side clients keep a path that no
// chaos test can take away.
type FailoverChainOutput struct {
	PrimaryContainerName   string           `toml:"primary_container_name"`
	SecondaryContainerName string           `toml:"secondary_container_name"`
	PrimaryNode            *blockchain.Node `toml:"primary_node"`
	SecondaryNode          *blockchain.Node `toml:"secondary_node"`
}

// proxyLauncher creates one proxy container in front of upstream. started=false
// creates the container without running it.
type proxyLauncher func(
	ctx context.Context,
	image string,
	containerName string,
	upstream *blockchain.Node,
	started bool,
) (*blockchain.Node, error)

func configureRPCFailover(
	ctx context.Context,
	family string,
	cfg *FailoverInput,
	outputs []*blockchain.Output,
	launch proxyLauncher,
) (*FailoverOutput, chainreg.LocalNetworkFinalizer, error) {
	if launch == nil {
		return nil, nil, fmt.Errorf("%s RPC failover proxy launcher is nil", family)
	}
	image := cfg.Image
	if image == "" {
		image = DefaultProxyImage
	}

	result := &FailoverOutput{
		Image:  image,
		Chains: make(map[string]*FailoverChainOutput),
	}
	directNodes := make(map[string][]*blockchain.Node)
	finalize := func() {
		restoreDirectNodes(outputs, directNodes, result.Chains)
	}

	for _, output := range outputs {
		if output == nil || output.Family != family {
			continue
		}
		if _, seen := result.Chains[output.ChainID]; seen {
			finalize()
			return nil, nil, fmt.Errorf("%s chain %s appears more than once; proxy container names would collide", family, output.ChainID)
		}
		if len(output.Nodes) == 0 || output.Nodes[0] == nil {
			finalize()
			return nil, nil, fmt.Errorf("%s chain %s has no direct RPC node to proxy", family, output.ChainID)
		}

		nodes := append([]*blockchain.Node(nil), output.Nodes...)
		baseName := strings.TrimPrefix(output.ContainerName, "/")
		if baseName == "" {
			baseName = family + "-" + output.ChainID
		}
		primaryName := baseName + PrimarySuffix
		secondaryName := baseName + SecondarySuffix

		primaryNode, err := launch(ctx, image, primaryName, nodes[0], true)
		if err != nil {
			finalize()
			return nil, nil, fmt.Errorf("launching primary RPC proxy for %s chain %s: %w", family, output.ChainID, err)
		}
		secondaryNode, err := launch(ctx, image, secondaryName, nodes[0], false)
		if err != nil {
			finalize()
			return nil, nil, fmt.Errorf("creating secondary RPC proxy for %s chain %s: %w", family, output.ChainID, err)
		}

		// Only the proxies are visible while standalone service configs are
		// generated. The stopped secondary makes the primary deterministic.
		directNodes[output.ChainID] = nodes
		output.Nodes = []*blockchain.Node{primaryNode, secondaryNode}
		result.Chains[output.ChainID] = &FailoverChainOutput{
			PrimaryContainerName:   primaryName,
			SecondaryContainerName: secondaryName,
			PrimaryNode:            primaryNode,
			SecondaryNode:          secondaryNode,
		}
	}

	if len(result.Chains) == 0 {
		return nil, nil, fmt.Errorf("%s RPC failover is enabled but no %s chains were configured", family, family)
	}
	return result, finalize, nil
}

// restoreDirectNodes puts the direct endpoint back at index 0 and appends the
// proxies, so a test can reach the chain directly and still address the proxies.
func restoreDirectNodes(
	outputs []*blockchain.Output,
	directNodes map[string][]*blockchain.Node,
	proxyOutputs map[string]*FailoverChainOutput,
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

// listener is one nginx server block: a port the proxy listens on and the
// upstream it forwards to.
type listener struct {
	port     string
	upstream string
}

// proxyPlan is the listener layout mirroring one upstream node. Families whose
// RPC and WebSocket endpoints share a port (EVM: 8545) get one listener;
// families that split them (Solana: 8899 RPC, 8900 WebSocket) get two, so the
// proxy preserves WebSocket instead of silently dropping it.
type proxyPlan struct {
	listeners []listener
	httpPort  string
	wsPort    string // empty when the upstream node exposes no WebSocket URL
}

func planProxy(node *blockchain.Node) (proxyPlan, error) {
	if node == nil || node.InternalHTTPUrl == "" {
		return proxyPlan{}, fmt.Errorf("direct node has no internal HTTP URL")
	}
	httpURL, err := parseProxyUpstream(node.InternalHTTPUrl, map[string]string{"http": "http", "https": "https"})
	if err != nil {
		return proxyPlan{}, fmt.Errorf("direct node HTTP URL: %w", err)
	}

	plan := proxyPlan{
		listeners: []listener{{port: httpURL.Port(), upstream: upstreamAddr(httpURL)}},
		httpPort:  httpURL.Port(),
	}
	if node.InternalWSUrl == "" {
		return plan, nil
	}

	wsURL, err := parseProxyUpstream(node.InternalWSUrl, map[string]string{"ws": "http", "wss": "https"})
	if err != nil {
		return proxyPlan{}, fmt.Errorf("direct node WebSocket URL: %w", err)
	}
	plan.wsPort = wsURL.Port()
	if wsURL.Scheme == httpURL.Scheme && wsURL.Host == httpURL.Host {
		// One listener carries both protocols; nginx upgrades in place.
		return plan, nil
	}
	if wsURL.Port() == httpURL.Port() {
		return proxyPlan{}, fmt.Errorf(
			"HTTP upstream %q and WebSocket upstream %q share port %s but differ; the proxy cannot mirror both",
			node.InternalHTTPUrl, node.InternalWSUrl, httpURL.Port(),
		)
	}
	plan.listeners = append(plan.listeners, listener{port: wsURL.Port(), upstream: upstreamAddr(wsURL)})
	return plan, nil
}

// parseProxyUpstream validates a direct node URL and rewrites its scheme to the
// HTTP scheme nginx proxies with. schemes maps accepted input schemes to that
// proxy scheme.
func parseProxyUpstream(raw string, schemes map[string]string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %w", raw, err)
	}
	proxyScheme, ok := schemes[parsed.Scheme]
	if !ok || parsed.Host == "" {
		return nil, fmt.Errorf("unsupported URL %q", raw)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, fmt.Errorf("RPC failover proxies require a host-only URL, got %q", raw)
	}
	if parsed.Port() == "" {
		return nil, fmt.Errorf("RPC failover proxies require an explicit port, got %q", raw)
	}
	parsed.Scheme = proxyScheme
	return parsed, nil
}

func upstreamAddr(u *url.URL) string {
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
}

func launchRPCProxy(
	ctx context.Context,
	image string,
	containerName string,
	upstream *blockchain.Node,
	started bool,
) (*blockchain.Node, error) {
	plan, err := planProxy(upstream)
	if err != nil {
		return nil, err
	}

	configFile, err := os.CreateTemp("", "ccv-rpc-proxy-*.conf")
	if err != nil {
		return nil, fmt.Errorf("creating nginx config: %w", err)
	}
	configPath := configFile.Name()
	defer func() { _ = os.Remove(configPath) }()
	if _, err := configFile.WriteString(nginxConfig(plan.listeners)); err != nil {
		_ = configFile.Close()
		return nil, fmt.Errorf("writing nginx config: %w", err)
	}
	if err := configFile.Close(); err != nil {
		return nil, fmt.Errorf("closing nginx config: %w", err)
	}

	exposed := make([]string, 0, len(plan.listeners))
	for _, l := range plan.listeners {
		exposed = append(exposed, l.port+"/tcp")
	}
	req := testcontainers.ContainerRequest{
		Image:        image,
		Name:         containerName,
		Labels:       framework.DefaultTCLabels(),
		Networks:     []string{framework.DefaultNetworkName},
		ExposedPorts: exposed,
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {containerName},
		},
		Files: []testcontainers.ContainerFile{{
			HostFilePath:      configPath,
			ContainerFilePath: proxyConfigPath,
			FileMode:          0o644,
		}},
		WaitingFor: wait.ForListeningPort(plan.httpPort + "/tcp").
			WithStartupTimeout(proxyStartupTimeout),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          started,
	})
	if err != nil {
		return nil, fmt.Errorf("creating proxy container %s: %w", containerName, err)
	}

	node := &blockchain.Node{
		InternalHTTPUrl: fmt.Sprintf("http://%s:%s", containerName, plan.httpPort),
	}
	if plan.wsPort != "" {
		node.InternalWSUrl = fmt.Sprintf("ws://%s:%s", containerName, plan.wsPort)
	}
	if !started {
		// A container that was never started has no host port mapping yet. It
		// only needs internal URLs: the failover test starts it from inside the
		// docker network, and the direct node covers test-side access.
		return node, nil
	}

	host, err := framework.GetHostWithContext(ctx, container)
	if err != nil {
		return nil, fmt.Errorf("getting proxy container host: %w", err)
	}
	httpPort, err := container.MappedPort(ctx, plan.httpPort+"/tcp")
	if err != nil {
		return nil, fmt.Errorf("getting proxy container HTTP port: %w", err)
	}
	node.ExternalHTTPUrl = fmt.Sprintf("http://%s:%s", host, httpPort.Port())
	if plan.wsPort != "" {
		wsPort, err := container.MappedPort(ctx, plan.wsPort+"/tcp")
		if err != nil {
			return nil, fmt.Errorf("getting proxy container WebSocket port: %w", err)
		}
		node.ExternalWSUrl = fmt.Sprintf("ws://%s:%s", host, wsPort.Port())
	}
	return node, nil
}

func nginxConfig(listeners []listener) string {
	var servers strings.Builder
	for _, l := range listeners {
		fmt.Fprintf(&servers, `
    server {
        listen %s;

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
`, l.port, l.upstream)
	}

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
%s}
`, servers.String())
}
