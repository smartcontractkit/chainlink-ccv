package constructors

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pelletier/go-toml/v2"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"
)

// messageSentFilterRegistered reports whether the node's log poller has stored the named filter for chainID.
// It reads the table because the log poller's in-memory filters are empty until its first poll.
func messageSentFilterRegistered(ctx context.Context, ds sqlutil.DataSource, chainID *big.Int, name string) (bool, error) {
	var exists bool
	if err := ds.GetContext(ctx, &exists,
		`SELECT EXISTS (SELECT 1 FROM evm.log_poller_filters WHERE evm_chain_id = $1::numeric AND name = $2)`,
		chainID.String(), name); err != nil {
		return false, fmt.Errorf("failed to read log poller filter %s: %w", name, err)
	}
	return exists, nil
}

// liveMessageSentFilters returns the filter names live verifier jobs need on sel. SKIP LOCKED drops specs
// locked by an uncommitted delete: JD cancels a job inside a transaction that commits only after Close.
func liveMessageSentFilters(ctx context.Context, ds sqlutil.DataSource, sel protocol.ChainSelector) (map[string]struct{}, error) {
	var configs []string
	if err := ds.SelectContext(ctx, &configs,
		`SELECT committee_verifier_config FROM ccv_committee_verifier_specs FOR KEY SHARE SKIP LOCKED`); err != nil {
		return nil, fmt.Errorf("failed to read committee verifier specs: %w", err)
	}
	key := strconv.FormatUint(uint64(sel), 10)
	live := make(map[string]struct{}, len(configs))
	for _, raw := range configs {
		var cfg commit.Config
		if err := toml.Unmarshal([]byte(raw), &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse committee verifier spec: %w", err)
		}
		if onRamp, ok := cfg.OnRampAddresses[key]; ok {
			live[evm.MessageSentFilterName(cfg.VerifierID, common.HexToAddress(onRamp))] = struct{}{}
		}
	}
	return live, nil
}

// newLogPollerConfig wires a chain's source reader to the node's log poller and database.
func newLogPollerConfig(ds sqlutil.DataSource, chain legacyevm.Chain, sel protocol.ChainSelector, verifierID string) *evm.LogPollerConfig {
	return &evm.LogPollerConfig{
		LogPoller:  chain.LogPoller(),
		VerifierID: verifierID,
		Retention:  evm.DefaultMessageSentLogRetention,
		Ready:      new(atomic.Bool),
		FilterRegistered: func(ctx context.Context, name string) (bool, error) {
			return messageSentFilterRegistered(ctx, ds, chain.ID(), name)
		},
		LiveFilters: func(ctx context.Context) (map[string]struct{}, error) {
			return liveMessageSentFilters(ctx, ds, sel)
		},
	}
}
