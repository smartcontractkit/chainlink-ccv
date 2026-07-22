package evm

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	evmconfig "github.com/smartcontractkit/chainlink-evm/pkg/config"
	"github.com/smartcontractkit/chainlink-evm/pkg/config/chaintype"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
)

const (
	// TXM v2 requires a block time of at least two seconds. It also uses head
	// notifications for fee updates, so this is only a retry cadence fallback.
	defaultTXMBlockTime = 2 * time.Second
	// HTTP polling keeps the production head tracker usable for deployments that
	// include HTTP-only RPCs. All-WebSocket pools retain subscriptions.
	defaultNewHeadsPollInterval = time.Second
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

	// CTF describes generic development chains as "anvil" and older configs use
	// "ethereum". Neither is a chainlink-evm ChainType; leaving the upstream
	// default in place selects generic EVM behavior. Recognized L2 types still
	// override the default and receive their chain-specific handling.
	chainTypeName := strings.TrimSpace(info.Type)
	switch chainTypeName {
	case "", "anvil", "ethereum":
	default:
		chainType := chaintype.FromSlug(chainTypeName)
		if !chainType.IsValid() {
			return nil, fmt.Errorf("unsupported EVM chain type %q", info.Type)
		}
		chain.ChainType = chaintype.NewConfig(chainTypeName)
	}

	// The standalone database does not contain chainlink-core's evm.heads schema,
	// so use the production tracker with its supported in-memory saver mode.
	chain.HeadTracker.PersistenceEnabled = new(false)
	// Preserve standalone CCV's finalization semantics. Generic chainlink-evm
	// defaults use a deeper confirmation window, which delays Finality=0 messages
	// beyond CCV's verifier and E2E execution deadlines on development chains.
	chain.FinalityDepth = new(uint32(vtypes.ConfirmationDepth))
	// These services are not consumers of the standalone accessor. Disabling
	// them keeps this lifecycle focused on the production HeadTracker and TXM.
	chain.LogBroadcasterEnabled = new(false)
	chain.BalanceMonitor.Enabled = new(false)
	chain.Transactions.Enabled = new(true)
	chain.Transactions.ForwardersEnabled = new(false)
	chain.Transactions.TransactionManagerV2.Enabled = new(true)
	chain.Transactions.TransactionManagerV2.BlockTime = commonconfig.MustNewDuration(defaultTXMBlockTime)

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
	if err := commonconfig.Validate(tomlConfig); err != nil {
		return nil, fmt.Errorf("invalid chainlink-evm config for chain %s: %w", info.ChainID, err)
	}
	if err := (evmtoml.EVMConfigs{tomlConfig}).ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid chainlink-evm config for chain %s: %w", info.ChainID, err)
	}
	return evmconfig.NewTOMLChainScopedConfig(tomlConfig), nil
}

// toChainlinkEVMNode deliberately maps only the endpoint subset owned by CCV.
// chainlink-evm-only options such as SendOnly, Order, and IsLoadBalancedRPC
// remain unset and therefore retain their upstream behavior.
func toChainlinkEVMNode(info Info, index int, configured Node) (*evmtoml.Node, bool, error) {
	httpURL := firstNonEmpty(configured.InternalHTTPUrl, configured.ExternalHTTPUrl)
	if httpURL == "" {
		return nil, false, fmt.Errorf("EVM chain %s node %d has no HTTP RPC URL", info.ChainID, index)
	}
	parsedHTTP, err := commonconfig.ParseURL(httpURL)
	if err != nil {
		return nil, false, fmt.Errorf("EVM chain %s node %d has invalid HTTP RPC URL: %w", info.ChainID, index, err)
	}

	wsURL := firstNonEmpty(configured.InternalWSUrl, configured.ExternalWSUrl)
	var parsedWS *commonconfig.URL
	if wsURL != "" {
		parsedWS, err = commonconfig.ParseURL(wsURL)
		if err != nil {
			return nil, false, fmt.Errorf("EVM chain %s node %d has invalid WebSocket RPC URL: %w", info.ChainID, index, err)
		}
	}

	name := nodeName(info, index)
	return &evmtoml.Node{
		Name:    &name,
		HTTPURL: parsedHTTP,
		WSURL:   parsedWS,
	}, parsedWS == nil, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func nodeName(info Info, index int) string {
	base := strings.TrimSpace(info.UniqueChainName)
	if base == "" {
		base = "evm-" + info.ChainID
	}
	if len(info.Nodes) == 1 {
		return base
	}
	return fmt.Sprintf("%s-%d", base, index+1)
}
