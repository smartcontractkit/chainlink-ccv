package evm

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
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

func ptr[T any](v T) *T { return &v }

func CreateHealthyMultiNodeClient(
	ctx context.Context,
	infos chainaccess.Infos[Info],
	lggr logger.Logger,
	chainSelector protocol.ChainSelector,
) (client.Client, error) {
	info, err := infos.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to get blockchain info for chain selector %v: %w", chainSelector, err)
	}
	return CreateMultiNodeClientFromInfo(ctx, info, lggr)
}

// CreateMultiNodeClientFromInfo creates and starts chainlink-evm's production
// multi-node client. Every configured node is registered with the pool, allowing
// the pool to move reads and writes away from unhealthy RPCs.
func CreateMultiNodeClientFromInfo(ctx context.Context, info Info, lggr logger.Logger) (client.Client, error) {
	chainClient, _, err := newMultiNodeClientFromInfo(info, lggr)
	if err != nil {
		return nil, err
	}
	if err := chainClient.Dial(ctx); err != nil {
		chainClient.Close()
		return nil, fmt.Errorf("failed to dial EVM client for chain %s: %w", info.ChainID, err)
	}
	return chainClient, nil
}

func newMultiNodeClientFromInfo(info Info, lggr logger.Logger) (client.Client, *evmconfig.ChainScoped, error) {
	chainConfig, err := newChainConfig(info)
	if err != nil {
		return nil, nil, err
	}

	chainClient, err := client.NewEvmClient(
		chainConfig.EVM().NodePool(),
		chainConfig.EVM(),
		chainConfig.EVM().NodePool().Errors(),
		lggr,
		chainConfig.EVM().ChainID(),
		chainConfig.Nodes(),
		chainConfig.EVM().ChainType(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create EVM client for chain %s: %w", info.ChainID, err)
	}

	lggr.Infow("Created production multi-node EVM client",
		"chainID", info.ChainID,
		"nodeCount", len(chainConfig.Nodes()),
		"selectionMode", chainConfig.EVM().NodePool().SelectionMode(),
	)
	return chainClient, chainConfig, nil
}

// newChainConfig translates the intentionally small standalone config into the
// full chainlink-evm configuration used by its client, head tracker, gas
// estimator, and transaction manager. Chain-specific upstream defaults are used
// wherever they exist.
func newChainConfig(info Info) (*evmconfig.ChainScoped, error) {
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
	chain.HeadTracker.PersistenceEnabled = ptr(false)
	// These services are not consumers of the standalone accessor. Disabling
	// them keeps this lifecycle focused on the production HeadTracker and TXM.
	chain.LogBroadcasterEnabled = ptr(false)
	chain.BalanceMonitor.Enabled = ptr(false)
	chain.Transactions.Enabled = ptr(true)
	chain.Transactions.ForwardersEnabled = ptr(false)
	chain.Transactions.TransactionManagerV2.Enabled = ptr(true)
	chain.Transactions.TransactionManagerV2.BlockTime = commonconfig.MustNewDuration(defaultTXMBlockTime)

	nodes := make(evmtoml.EVMNodes, 0, len(info.Nodes))
	usesHTTPPolling := false
	for i, configured := range info.Nodes {
		httpURL := firstNonEmpty(configured.InternalHTTPUrl, configured.ExternalHTTPUrl)
		if httpURL == "" {
			return nil, fmt.Errorf("EVM chain %s node %d has no HTTP RPC URL", info.ChainID, i)
		}
		parsedHTTP, err := commonconfig.ParseURL(httpURL)
		if err != nil {
			return nil, fmt.Errorf("EVM chain %s node %d has invalid HTTP RPC URL: %w", info.ChainID, i, err)
		}

		wsURL := firstNonEmpty(configured.InternalWSUrl, configured.ExternalWSUrl)
		var parsedWS *commonconfig.URL
		if wsURL == "" {
			usesHTTPPolling = true
		} else {
			parsedWS, err = commonconfig.ParseURL(wsURL)
			if err != nil {
				return nil, fmt.Errorf("EVM chain %s node %d has invalid WebSocket RPC URL: %w", info.ChainID, i, err)
			}
		}

		name := nodeName(info, i)
		node := &evmtoml.Node{
			Name:    &name,
			HTTPURL: parsedHTTP,
			WSURL:   parsedWS,
		}
		nodes = append(nodes, node)
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
