package chaos

// RPC failover proxy controls for chaos tests. devenv can put a pair of
// independently controllable reverse proxies in front of each chain's RPC
// endpoint (see build/devenv/localnetwork); these helpers find those proxies in
// the environment output and start or stop them, which is how a test takes one
// endpoint away from a multi-node client and watches it move to the other.
//
// Everything here is chain-family-agnostic: a Solana test drives the same
// helpers as an EVM one, passing its own selectors.

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/localnetwork"
	devenvutil "github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
)

const (
	// RPCProxyCommandTimeout bounds a single docker start/stop.
	RPCProxyCommandTimeout = 30 * time.Second
	// RPCProxyReadyTimeout is how long a started proxy has to accept traffic.
	RPCProxyReadyTimeout = 15 * time.Second

	rpcProxyProbeTimeout   = 5 * time.Second
	rpcProxyReadyTick      = 250 * time.Millisecond
	rpcProxyCleanupTimeout = 15 * time.Second
)

// RPCFailoverOutputFor returns the failover proxy topology devenv recorded for
// family. It errors when the environment was not brought up with rpc_failover
// enabled for that family, which is the useful failure for a test to report.
func RPCFailoverOutputFor(cfg *ccv.Cfg, family string) (*localnetwork.FailoverOutput, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil devenv config")
	}
	localNetwork := cfg.LocalNetworks[family]
	if localNetwork == nil || len(localNetwork.Output) == 0 {
		return nil, fmt.Errorf("no %s local-network output; bring the environment up with the rpc_failover profile", family)
	}
	output, err := devenvutil.OpaqueToConcreteStrict[localnetwork.Output](localNetwork.Output)
	if err != nil {
		return nil, fmt.Errorf("decoding %s local-network output: %w", family, err)
	}
	if output.RPCFailover == nil || len(output.RPCFailover.Chains) == 0 {
		return nil, fmt.Errorf("%s local-network output has no RPC failover proxies", family)
	}
	return output.RPCFailover, nil
}

// RPCFailoverChainFor returns the proxy pair in front of the chain identified
// by selector, resolving the family and chain ID from the selector itself.
func RPCFailoverChainFor(cfg *ccv.Cfg, selector uint64) (*localnetwork.FailoverChainOutput, error) {
	family, err := chain_selectors.GetSelectorFamily(selector)
	if err != nil {
		return nil, fmt.Errorf("resolving family for selector %d: %w", selector, err)
	}
	chainID, err := chain_selectors.GetChainIDFromSelector(selector)
	if err != nil {
		return nil, fmt.Errorf("resolving chain ID for selector %d: %w", selector, err)
	}
	failover, err := RPCFailoverOutputFor(cfg, family)
	if err != nil {
		return nil, err
	}
	chain := failover.Chains[chainID]
	if chain == nil {
		return nil, fmt.Errorf("no RPC failover proxies for %s chain %s", family, chainID)
	}
	return chain, nil
}

// DirectRPCNode returns the unproxied node for selector. devenv restores it at
// index 0 of the serialized blockchain output before the proxies, so a test
// keeps a path to the chain that no proxy outage can take away.
func DirectRPCNode(cfg *ccv.Cfg, selector uint64) (*blockchain.Node, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil devenv config")
	}
	chainID, err := chain_selectors.GetChainIDFromSelector(selector)
	if err != nil {
		return nil, fmt.Errorf("resolving chain ID for selector %d: %w", selector, err)
	}
	for _, chain := range cfg.Blockchains {
		if chain == nil || chain.Out == nil || chain.Out.ChainID != chainID {
			continue
		}
		if len(chain.Out.Nodes) == 0 || chain.Out.Nodes[0] == nil {
			return nil, fmt.Errorf("chain %s has no nodes in the stored environment output", chainID)
		}
		return chain.Out.Nodes[0], nil
	}
	return nil, fmt.Errorf("chain %s not found in the stored environment output", chainID)
}

// SetRPCProxyRunning starts or stops one failover proxy. When starting, it
// waits until the proxy answers a config check, so a test that sends a message
// straight after does not race the container coming up.
//
// The readiness probe assumes the nginx-based localnetwork.DefaultProxyImage.
func SetRPCProxyRunning(ctx context.Context, containerName string, running bool) error {
	action := "stop"
	if running {
		action = "start"
	}
	zerolog.Ctx(ctx).Info().
		Str("container", containerName).
		Str("action", action).
		Msg("changing RPC proxy state")

	if out, err := RunDocker(ctx, RPCProxyCommandTimeout, action, containerName); err != nil {
		return fmt.Errorf("docker %s %s: %w: %s", action, containerName, err, strings.TrimSpace(string(out)))
	}
	if !running {
		return nil
	}
	return waitForRPCProxy(ctx, containerName)
}

// RestoreRPCProxies puts one chain's proxies back the way devenv left them:
// primary running, secondary stopped. Failures are logged rather than returned
// so it is safe to defer from a test cleanup that must not fail the run.
func RestoreRPCProxies(ctx context.Context, chain *localnetwork.FailoverChainOutput) {
	if chain == nil {
		return
	}
	for containerName, running := range map[string]bool{
		chain.PrimaryContainerName:   true,
		chain.SecondaryContainerName: false,
	} {
		action := "stop"
		if running {
			action = "start"
		}
		out, err := RunDocker(context.WithoutCancel(ctx), rpcProxyCleanupTimeout, action, containerName)
		if err != nil {
			zerolog.Ctx(ctx).Error().Err(err).
				Str("container", containerName).
				Str("action", action).
				Str("output", strings.TrimSpace(string(out))).
				Msg("failed to restore RPC proxy state")
		}
	}
}

// waitForRPCProxy polls until the proxy accepts a config check. Each probe gets
// a deadline shorter than the readiness window so a stuck exec is retried
// rather than consuming the whole window on one attempt.
func waitForRPCProxy(ctx context.Context, containerName string) error {
	deadline := time.Now().Add(RPCProxyReadyTimeout)
	for {
		if _, err := RunDocker(ctx, rpcProxyProbeTimeout, "exec", containerName, "nginx", "-t"); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("RPC proxy %s did not become ready within %s", containerName, RPCProxyReadyTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(rpcProxyReadyTick):
		}
	}
}

// RunDocker runs a docker command under its own deadline and returns its
// combined output. A test context alone only unblocks when the test finishes,
// so a wedged daemon or CLI would hang the call indefinitely instead of
// failing it.
func RunDocker(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
}
