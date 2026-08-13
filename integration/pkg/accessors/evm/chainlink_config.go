package evm

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	evmconfig "github.com/smartcontractkit/chainlink-evm/pkg/config"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
)

const (
	// TXM v2 requires a block time of at least two seconds. It also uses head
	// notifications for fee updates, so this is only a retry cadence fallback.
	defaultTXMBlockTime = 2 * time.Second
	// HTTP polling keeps the production head tracker usable for deployments that
	// include HTTP-only RPCs. All-WebSocket pools retain subscriptions.
	defaultNewHeadsPollInterval = time.Second
	// orphanRecoveryGracePeriod is how long a restarted process waits for
	// transactions left in flight by its predecessor to confirm on their own before
	// replacing them. A transaction that is merely slow mines within this window and
	// is left alone; replacing one needlessly discards a real execution and makes the
	// executor send another. See standaloneChain.recoverOrphanedTransactions.
	orphanRecoveryGracePeriod = 90 * time.Second
	// orphanRecoveryRPCTimeout bounds a single nonce read during orphan recovery. Recovery runs on a
	// goroutine Close waits for, so every network call it makes needs a deadline of its own rather
	// than relying on the RPC client having one.
	orphanRecoveryRPCTimeout = 30 * time.Second
)

// newChainlinkEVMConfig is the single adapter from CCV's focused standalone
// configuration to chainlink-evm's full configuration model. Keeping the
// boundary explicit prevents additions to the upstream config from silently
// becoming operator-facing CCV settings. Chain-specific upstream defaults are
// used for every setting that CCV does not intentionally override below.
func newChainlinkEVMConfig(info Info) (*evmconfig.ChainScoped, error) {
	chainID, ok := new(big.Int).SetString(info.ChainID, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse EVM chain ID %q", info.ChainID)
	}
	sqlChainID := sqlutil.New(chainID)
	chain := evmtoml.Defaults(sqlChainID)

	// The standalone database does not contain chainlink-core's evm.heads schema,
	// so use the production tracker with its supported in-memory saver mode. The
	// known delta: a restart starts the tracker cold — it re-syncs from RPC where
	// the node resumed from persisted heads, which costs catch-up time on restart,
	// not correctness.
	chain.HeadTracker.PersistenceEnabled = new(false)
	if info.FinalityDepth == 0 {
		// chain.FinalityDepth is deliberately left at the chain-specific upstream
		// default: evmtoml.Chain.ValidateConfig rejects a depth below 1 whether or
		// not finality tags are enabled, so it cannot be zeroed out here.
		chain.FinalityTagEnabled = new(true)
	} else {
		// A positive operator value explicitly selects depth-based finality,
		// including on chains whose upstream default enables finality tags.
		chain.FinalityTagEnabled = new(false)
		chain.FinalityDepth = new(info.FinalityDepth)
	}
	// These services are not consumers of the standalone accessor. Disabling
	// them keeps this lifecycle focused on the production HeadTracker and TXM.
	//
	// The balance monitor stays off deliberately: nothing in the standalone
	// lifecycle constructs chainlink-evm's balance monitor, so the flag has no
	// consumer here, and the executor's transmitter key is generated fresh at
	// first boot rather than carried over. Funding is a runbook step with an
	// external balance alert on the transmitter address instead; see the
	// migration procedure's "Fund the executor" step.
	chain.LogBroadcasterEnabled = new(false)
	chain.BalanceMonitor.Enabled = new(false)
	// These settings configure TXM v2 but do not start it. standaloneChain builds
	// and starts a TXM only in NewContractTransmitter, which runs when bootstrap
	// injects a keystore into an accessor that has an OffRamp address. Source-only
	// deployments such as the verifier carry no chain_configuration, so they never
	// construct a TXM and produce no idle TXM goroutines or logs.
	chain.Transactions.Enabled = new(true)
	chain.Transactions.ForwardersEnabled = new(false)
	chain.Transactions.TransactionManagerV2.Enabled = new(true)
	// AutoPurge is deliberately left at its upstream default of off, which means TXM
	// v2 runs without a stuck transaction detector. Turning it on is worth doing, but
	// not here: upstream validation then also requires GasEstimator.BumpThreshold and
	// AutoPurge.MinAttempts, and both change fee behavior for every transaction
	// rather than only stuck ones. Restart-orphaned transactions are handled without
	// it (see standaloneChain.recoverOrphanedTransactions).
	blockTime := info.TXMBlockTime
	if blockTime == 0 {
		blockTime = defaultTXMBlockTime
	}
	chain.Transactions.TransactionManagerV2.BlockTime = commonconfig.MustNewDuration(blockTime)

	nodes := make(evmtoml.EVMNodes, 0, len(info.Nodes))
	usesHTTPPolling := false
	for i, configured := range info.Nodes {
		node, usesPolling, err := toChainlinkEVMNode(info, i, configured)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
		usesHTTPPolling = usesHTTPPolling || usesPolling
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("EVM chain %s has no RPC nodes", info.ChainID)
	}
	if usesHTTPPolling {
		chain.NodePool.NewHeadsPollInterval = commonconfig.MustNewDuration(defaultNewHeadsPollInterval)
	}

	tomlConfig := &evmtoml.EVMConfig{
		ChainID: sqlChainID,
		Chain:   chain,
		Nodes:   nodes,
	}
	// The generic validator invokes EVMConfig and all nested ValidateConfig
	// methods. EVMConfigs.ValidateConfig separately enforces uniqueness across
	// chain and node keys; chainlink-evm requires both validation layers.
	if err := commonconfig.Validate(tomlConfig); err != nil {
		return nil, fmt.Errorf("invalid chainlink-evm config for chain %s: %w", info.ChainID, err)
	}
	if err := (evmtoml.EVMConfigs{tomlConfig}).ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid chainlink-evm config for chain %s: %w", info.ChainID, err)
	}
	return evmconfig.NewTOMLChainScopedConfig(tomlConfig), nil
}

// toChainlinkEVMNode deliberately maps only the subset owned by CCV: the endpoint
// pair and the node's selection priority. chainlink-evm-only options such as
// SendOnly and IsLoadBalancedRPC remain unset and therefore retain their upstream
// behavior.
func toChainlinkEVMNode(info Info, index int, configured Node) (*evmtoml.Node, bool, error) {
	httpURL := strings.TrimSpace(configured.HTTPUrl)
	if httpURL == "" {
		return nil, false, fmt.Errorf(
			"EVM chain %s node %d has no HTTP RPC URL; WebSocket-only nodes are not supported",
			info.ChainID,
			index,
		)
	}
	parsedHTTP, err := commonconfig.ParseURL(httpURL)
	if err != nil {
		return nil, false, fmt.Errorf("EVM chain %s node %d has invalid HTTP RPC URL: %w", info.ChainID, index, err)
	}

	wsURL := strings.TrimSpace(configured.WSUrl)
	var parsedWS *commonconfig.URL
	if wsURL != "" {
		parsedWS, err = commonconfig.ParseURL(wsURL)
		if err != nil {
			return nil, false, fmt.Errorf("EVM chain %s node %d has invalid WebSocket RPC URL: %w", info.ChainID, index, err)
		}
	}

	name := nodeName(info, index, configured)
	node := &evmtoml.Node{
		Name:    &name,
		HTTPURL: parsedHTTP,
		WSURL:   parsedWS,
	}
	// Zero means the operator set no priority, so leave Order nil and let chainlink-evm apply its
	// own default. A non-zero value is passed straight through; the upstream validator rejects
	// anything outside 1..100 when the config is built.
	if configured.Order != 0 {
		order := configured.Order
		node.Order = &order
	}
	return node, parsedWS == nil, nil
}

func nodeName(info Info, index int, configured Node) string {
	if name := strings.TrimSpace(configured.Name); name != "" {
		return name
	}
	return defaultNodeName(info, index)
}
