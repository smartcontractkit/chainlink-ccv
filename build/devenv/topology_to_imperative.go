package ccv

import (
	"strconv"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// nopInputsFromTopology converts the topology's NOP slice into the imperative
// changeset input shape introduced in Phase C. The dev-env continues to keep a
// single EnvironmentTopology as its source of truth and slices it per call when
// invoking the now-imperative chainlink-ccv changesets.
func nopInputsFromTopology(topology *ccvdeployment.EnvironmentTopology) []ccvchangesets.NOPInput {
	if topology == nil || topology.NOPTopology == nil {
		return nil
	}
	out := make([]ccvchangesets.NOPInput, len(topology.NOPTopology.NOPs))
	for i, nop := range topology.NOPTopology.NOPs {
		out[i] = ccvchangesets.NOPInput{
			Alias:                 ccvshared.NOPAlias(nop.Alias),
			SignerAddressByFamily: nop.SignerAddressByFamily,
			Mode:                  nop.GetMode(),
		}
	}
	return out
}

// committeeInputFromTopology slices the given committee out of the topology and
// converts it into the imperative ApplyVerifierConfig committee input.
func committeeInputFromTopology(committee ccvdeployment.CommitteeConfig) ccvchangesets.CommitteeInput {
	aggregators := make([]ccvchangesets.AggregatorRef, len(committee.Aggregators))
	for i, agg := range committee.Aggregators {
		aggregators[i] = ccvchangesets.AggregatorRef{
			Name:                         agg.Name,
			Address:                      agg.Address,
			InsecureAggregatorConnection: agg.InsecureAggregatorConnection,
		}
	}

	chainConfigs := make(map[uint64]ccvchangesets.CommitteeChainMembership, len(committee.ChainConfigs))
	for chainSelectorStr, chainCfg := range committee.ChainConfigs {
		sel, err := strconv.ParseUint(chainSelectorStr, 10, 64)
		if err != nil {
			// Topology validation rejects non-uint64 keys; defensive skip.
			continue
		}
		chainConfigs[sel] = ccvchangesets.CommitteeChainMembership{
			NOPAliases: ccvshared.ConvertStringToNopAliases(chainCfg.NOPAliases),
		}
	}

	return ccvchangesets.CommitteeInput{
		Qualifier:    committee.Qualifier,
		Aggregators:  aggregators,
		ChainConfigs: chainConfigs,
	}
}

// executorPoolInputFromTopology converts a topology executor pool into the
// imperative ApplyExecutorConfig pool input.
func executorPoolInputFromTopology(pool ccvdeployment.ExecutorPoolConfig) ccvchangesets.ExecutorPoolInput {
	chainConfigs := make(map[uint64]ccvchangesets.ChainExecutorPoolMembership, len(pool.ChainConfigs))
	for chainSelectorStr, chainCfg := range pool.ChainConfigs {
		sel, err := strconv.ParseUint(chainSelectorStr, 10, 64)
		if err != nil {
			continue
		}
		chainConfigs[sel] = ccvchangesets.ChainExecutorPoolMembership{
			NOPAliases:        ccvshared.ConvertStringToNopAliases(chainCfg.NOPAliases),
			ExecutionInterval: chainCfg.ExecutionInterval,
		}
	}

	return ccvchangesets.ExecutorPoolInput{
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

// committeeChainSelectorsFromTopology returns the destination chain selectors a
// committee is configured for. Used to seed the imperative GenerateAggregatorConfig
// changeset, which expects chain selectors directly rather than a topology blob.
func committeeChainSelectorsFromTopology(committee ccvdeployment.CommitteeConfig) []uint64 {
	out := make([]uint64, 0, len(committee.ChainConfigs))
	for chainSelectorStr := range committee.ChainConfigs {
		sel, err := strconv.ParseUint(chainSelectorStr, 10, 64)
		if err != nil {
			continue
		}
		out = append(out, sel)
	}
	return out
}
