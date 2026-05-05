package changesets

import (
	"time"

	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// NOPInput is the imperative per-NOP input shared by the offchain-only changesets
// that take a slice of NOP descriptions (verifier and executor config publishing).
//
// SignerAddressByFamily is consulted by the verifier changeset and falls back to a
// JD lookup when empty for the relevant family. The executor changeset ignores
// signer addresses — only Mode and Alias are consulted there.
//
// Mode defaults to NOPModeCL when empty.
type NOPInput struct {
	Alias                 shared.NOPAlias
	SignerAddressByFamily map[string]string
	Mode                  shared.NOPMode
}

// GetMode returns the NOP's mode, defaulting to NOPModeCL when unset.
func (n NOPInput) GetMode() shared.NOPMode {
	if n.Mode == "" {
		return shared.NOPModeCL
	}
	return n.Mode
}

// CommitteeInput is the imperative per-committee input for ApplyVerifierConfig.
// It replaces the topology-driven committee lookup.
//
// ChainConfigs maps chain selector → per-chain NOP membership. When empty, every
// NOP listed in NOPs (or filtered through TargetNOPs) participates on every chain
// the committee is deployed on (mirrors the per-NOP "all chains" behaviour used
// by AddNOPOffchain's verifier-job provisioning).
type CommitteeInput struct {
	Qualifier    string
	Aggregators  []AggregatorRef
	ChainConfigs map[uint64]CommitteeChainMembership
}

// CommitteeChainMembership lists which NOPs participate in the committee on a
// given source chain. Mirrors the topology-side ChainCommitteeConfig.NOPAliases
// without the unrelated onchain fields (threshold, fee aggregator, allowlist
// admin) — those are not consumed by verifier job-spec generation.
type CommitteeChainMembership struct {
	NOPAliases []shared.NOPAlias
}

// ExecutorPoolInput is the imperative per-pool input for ApplyExecutorConfig.
// It replaces the topology-driven executor pool lookup.
//
// ChainConfigs lists per-chain NOP membership and execution interval; the
// remaining fields carry pool-wide tuning that the topology version ferried
// through a single ExecutorPoolConfig struct.
type ExecutorPoolInput struct {
	ChainConfigs      map[uint64]ChainExecutorPoolMembership
	IndexerQueryLimit uint64
	BackoffDuration   time.Duration
	LookbackWindow    time.Duration
	ReaderCacheExpiry time.Duration
	MaxRetryDuration  time.Duration
	WorkerCount       int
	NtpServer         string
}

// ChainExecutorPoolMembership lists the NOPs participating in an executor pool
// on a given destination chain plus the per-chain execution interval.
type ChainExecutorPoolMembership struct {
	NOPAliases        []shared.NOPAlias
	ExecutionInterval time.Duration
}

// buildNOPModes returns the alias→mode map used by ManageJobProposals to decide
// which NOPs go through JD proposal vs. standalone job-spec emission.
func buildNOPModes(nops []NOPInput) map[shared.NOPAlias]shared.NOPMode {
	modes := make(map[shared.NOPAlias]shared.NOPMode, len(nops))
	for _, nop := range nops {
		modes[nop.Alias] = nop.GetMode()
	}
	return modes
}

// filterCLModeNOPs keeps only the aliases whose NOPInput has Mode == NOPModeCL.
// CL-mode NOPs are the ones whose chain support is validated against JD; standalone
// NOPs are skipped because the operator runs the node out-of-band.
func filterCLModeNOPs(aliases []shared.NOPAlias, nops []NOPInput) []shared.NOPAlias {
	modeByAlias := buildNOPModes(nops)
	filtered := make([]shared.NOPAlias, 0, len(aliases))
	for _, alias := range aliases {
		if mode, ok := modeByAlias[alias]; ok && mode == shared.NOPModeCL {
			filtered = append(filtered, alias)
		}
	}
	return filtered
}

// allNOPAliases returns every alias declared in nops, preserving input order.
func allNOPAliases(nops []NOPInput) []shared.NOPAlias {
	out := make([]shared.NOPAlias, len(nops))
	for i, nop := range nops {
		out[i] = nop.Alias
	}
	return out
}
