package evmconfig

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
)

const (
	// DefaultTXMBlockTime is the retry cadence TXM v2 falls back to when the operator sets none
	// and the chain has no curated entry. TXM v2 requires a block time of at least two seconds
	// (upstream validation rejects less), so it is also the best legal value for every chain
	// whose real block interval is shorter. It also uses head notifications for fee updates, so
	// this is only a retry cadence fallback.
	DefaultTXMBlockTime = 2 * time.Second
	// DefaultNewHeadsPollInterval keeps the production head tracker usable for deployments that
	// include HTTP-only RPCs. All-WebSocket pools retain subscriptions.
	DefaultNewHeadsPollInterval = time.Second
)

// TXMBlockTimeSource identifies where a chain's effective TXM v2 block time came from. It rides
// along with the value so the fallback warning and the pre-cutover report can tell an operator
// apart from a default — and a chain-specific default from the generic 2s one.
type TXMBlockTimeSource string

const (
	// TXMBlockTimeOperator is an explicit txm_block_time (standalone config) or
	// Transactions.TransactionManagerV2.BlockTime (node config).
	TXMBlockTimeOperator TXMBlockTimeSource = "operator"
	// TXMBlockTimeCuratedDefault is the per-chain value from curatedTXMBlockTimeByChainID.
	TXMBlockTimeCuratedDefault TXMBlockTimeSource = "curated_chain_default"
	// TXMBlockTimeGenericFallback is DefaultTXMBlockTime: the chain has no curated entry.
	TXMBlockTimeGenericFallback TXMBlockTimeSource = "generic_fallback"
)

// curatedTXMBlockTimeByChainID holds the block interval of chains whose real block time is above
// the two-second floor upstream validation enforces — the only chains the generic fallback
// mistunes. TXM v2 rebroadcasts a transaction once it is RetryBlockThreshold (derived from the v1
// BumpThreshold, default 3) times BlockTime old, so the value must track the chain's real cadence:
// on a 12s chain the 2s fallback bumps fees at 6s instead of 36s, and on Rootstock's ~30s blocks it
// would bump before one block has passed. Chains at or below two seconds are deliberately absent —
// the floor already serves them. Values are the chains' publicly documented block intervals; when
// in doubt the entry errs high, since a slower-than-ideal bump cadence costs latency where a
// faster one burns fees.
var curatedTXMBlockTimeByChainID = map[string]time.Duration{
	"1":        12 * time.Second, // Ethereum mainnet
	"11155111": 12 * time.Second, // Ethereum Sepolia
	"17000":    12 * time.Second, // Ethereum Holesky
	"30":       30 * time.Second, // Rootstock (merge-mined)
	"100":      5 * time.Second,  // Gnosis
	"10200":    5 * time.Second,  // Gnosis Chiado
	"109":      5 * time.Second,  // Shibarium
	"592":      12 * time.Second, // Astar (Substrate)
	"964":      12 * time.Second, // Bittensor EVM (Substrate)
	"1116":     3 * time.Second,  // Core
	"2020":     3 * time.Second,  // Ronin
	"534352":   3 * time.Second,  // Scroll
}

// ResolveTXMBlockTime resolves the block time a chain will run: the operator's explicit value when
// set, then the curated per-chain default, then the generic fallback. BuildChainlinkEVMTOML writes
// the resolved value into the chainlink-evm config, and the runtime log and pre-cutover report read
// the source to say which of the three produced it.
func ResolveTXMBlockTime(info Info) (time.Duration, TXMBlockTimeSource) {
	if info.TXMBlockTime != 0 {
		return info.TXMBlockTime, TXMBlockTimeOperator
	}
	if curated, ok := curatedTXMBlockTimeByChainID[info.ChainID]; ok {
		return curated, TXMBlockTimeCuratedDefault
	}
	return DefaultTXMBlockTime, TXMBlockTimeGenericFallback
}

// BuildChainlinkEVMTOML builds and validates the full chainlink-evm TOML config for one chain,
// applying CCV's overrides on top of chain-specific upstream defaults. It is exported to the
// migration tooling through EffectiveChainConfigs, so the pre-cutover settings diff reads exactly
// what the standalone process will run.
func BuildChainlinkEVMTOML(info Info) (*evmtoml.EVMConfig, error) {
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
	blockTime, _ := ResolveTXMBlockTime(info)
	// A negative operator value must be an error here, not later: MustNewDuration panics on
	// negatives, and upstream validation would only see the value after it was built. The
	// standalone-format decode (a raw time.Duration) accepts "-5s" where the node-config decode
	// rejects it, so both paths funnel through this guard.
	if blockTime < 0 {
		return nil, fmt.Errorf(
			"EVM chain %s has a negative txm_block_time %s: use zero for the chain default or a value of at least 2s",
			info.ChainID, blockTime)
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
		chain.NodePool.NewHeadsPollInterval = commonconfig.MustNewDuration(DefaultNewHeadsPollInterval)
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
	return tomlConfig, nil
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
