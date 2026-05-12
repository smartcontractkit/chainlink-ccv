package changesets

import (
	"slices"
	"strconv"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// NOPInputsFromTopology converts an EnvironmentTopology's NOP slice into the
// imperative changeset input shape. Callers that keep an EnvironmentTopology
// as their source of truth (the dev-env, chainlink-deployments live envs) can
// slice it per call when invoking the offchain-only changesets.
func NOPInputsFromTopology(topology *ccvdeployment.EnvironmentTopology) []NOPInput {
	if topology == nil || topology.NOPTopology == nil {
		return nil
	}
	out := make([]NOPInput, len(topology.NOPTopology.NOPs))
	for i, nop := range topology.NOPTopology.NOPs {
		out[i] = NOPInput{
			Alias:                 shared.NOPAlias(nop.Alias),
			SignerAddressByFamily: nop.SignerAddressByFamily,
			Mode:                  nop.GetMode(),
		}
	}
	return out
}

// CommitteeInputFromTopology converts a topology CommitteeConfig into the
// imperative ApplyVerifierConfig committee input. The onchain-only fields
// (threshold, fee aggregator, allowlist admin) are intentionally not carried
// — those are written by the onchain changesets, not by the offchain
// verifier-config publisher.
func CommitteeInputFromTopology(committee ccvdeployment.CommitteeConfig) CommitteeInput {
	aggregators := make([]AggregatorRef, len(committee.Aggregators))
	for i, agg := range committee.Aggregators {
		aggregators[i] = AggregatorRef{
			Name:                         agg.Name,
			Address:                      agg.Address,
			InsecureAggregatorConnection: agg.InsecureAggregatorConnection,
		}
	}

	chainConfigs := make(map[uint64]CommitteeChainMembership, len(committee.ChainConfigs))
	for chainSelectorStr, chainCfg := range committee.ChainConfigs {
		sel, err := strconv.ParseUint(chainSelectorStr, 10, 64)
		if err != nil {
			// Topology validation rejects non-uint64 keys; defensive skip.
			continue
		}
		chainConfigs[sel] = CommitteeChainMembership{
			NOPAliases: shared.ConvertStringToNopAliases(chainCfg.NOPAliases),
		}
	}

	return CommitteeInput{
		Qualifier:    committee.Qualifier,
		Aggregators:  aggregators,
		ChainConfigs: chainConfigs,
	}
}

// ExecutorPoolInputFromTopology converts a topology ExecutorPoolConfig into the
// imperative ApplyExecutorConfig pool input.
func ExecutorPoolInputFromTopology(pool ccvdeployment.ExecutorPoolConfig) ExecutorPoolInput {
	chainConfigs := make(map[uint64]ChainExecutorPoolMembership, len(pool.ChainConfigs))
	for chainSelectorStr, chainCfg := range pool.ChainConfigs {
		sel, err := strconv.ParseUint(chainSelectorStr, 10, 64)
		if err != nil {
			continue
		}
		chainConfigs[sel] = ChainExecutorPoolMembership{
			NOPAliases:        shared.ConvertStringToNopAliases(chainCfg.NOPAliases),
			ExecutionInterval: chainCfg.ExecutionInterval,
		}
	}

	return ExecutorPoolInput{
		ChainConfigs:      chainConfigs,
		IndexerQueryLimit: pool.IndexerQueryLimit,
		BackoffDuration:   pool.BackoffDuration,
		LookbackWindow:    pool.LookbackWindow,
		ReaderCacheExpiry: pool.ReaderCacheExpiry,
		MaxRetryDuration:  pool.MaxRetryDuration,
		WorkerCount:       pool.WorkerCount,
		NtpServer:         pool.NtpServer,
	}
}

// CommitteeChainSelectorsFromTopology returns the destination chain selectors a
// committee is configured for. Used to seed the imperative GenerateAggregatorConfig
// changeset, which expects chain selectors directly rather than a topology blob.
// The returned slice is sorted so that downstream error messages and config
// generation are deterministic across calls.
func CommitteeChainSelectorsFromTopology(committee ccvdeployment.CommitteeConfig) []uint64 {
	out := make([]uint64, 0, len(committee.ChainConfigs))
	for chainSelectorStr := range committee.ChainConfigs {
		sel, err := strconv.ParseUint(chainSelectorStr, 10, 64)
		if err != nil {
			continue
		}
		out = append(out, sel)
	}
	slices.Sort(out)
	return out
}
