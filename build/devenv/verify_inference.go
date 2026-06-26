package ccv

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// State-inference verification is a permanent, unconditional part of devenv
// bring-up — the e2e gate for the topology-free refactor.
//
// Right after each topology-driven ApplyVerifierConfig / ApplyExecutorConfig, we
// reconstruct the same changeset input from live state (on-chain committee scans +
// JD for verifiers; persisted job specs for executors) and require it to equal the
// topology-derived input that was just applied. A mismatch — or any failure to
// reconstruct — fails the bring-up. This proves the state resolvers are correct
// against a real environment, so a live env (which has no topology to fall back on)
// can be driven entirely from inferred inputs.
//
// The only non-fatal outcome is genuinely-empty state: no JD client to map signers
// to NOPs, or nothing deployed/published yet. That is "nothing to compare," not a
// toggle — it is logged so it stays visible in run output.

// verifyCommitteeInference reconstructs a committee's per-chain membership from
// live on-chain state + JD and requires it to match the topology-derived
// CommitteeInput just applied. The committee verifier is deployed and its
// signature configs are set on-chain (ConfigureChainsForLanesFromTopology) before
// verifier job-spec generation runs, so on-chain state is present here.
func verifyCommitteeInference(
	e *deployment.Environment,
	committeeQualifier, family string,
	topo ccvchangesets.CommitteeInput,
) error {
	if e.Offchain == nil || len(e.NodeIDs) == 0 {
		L.Warn().Str("committee", committeeQualifier).Str("family", family).
			Msg("state inference: no JD client / node IDs on environment; cannot map on-chain signers to NOPs, skipping committee check")
		return nil
	}

	ctx := context.Background()
	ids, err := ccvchangesets.LoadNOPIdentities(ctx, *e)
	if err != nil {
		return fmt.Errorf("committee %q (family %q): load NOP identities from JD: %w", committeeQualifier, family, err)
	}

	state, err := ccvchangesets.CommitteeInputFromState(ctx, *e, ids, committeeQualifier, family)
	if err != nil {
		return fmt.Errorf("committee %q (family %q): reconstruct from state: %w", committeeQualifier, family, err)
	}

	if len(state.ChainConfigs) == 0 {
		L.Warn().Str("committee", committeeQualifier).Str("family", family).
			Msg("state inference: no on-chain committee config found; skipping committee check")
		return nil
	}

	if diffs := diffCommitteeMembership(topo, state); len(diffs) > 0 {
		L.Error().Str("committee", committeeQualifier).Str("family", family).
			Strs("mismatches", diffs).
			Msg("state inference mismatch vs topology-derived committee input")
		return fmt.Errorf("committee %q (family %q) state inference mismatch: %s", committeeQualifier, family, strings.Join(diffs, "; "))
	}

	L.Info().Str("committee", committeeQualifier).Str("family", family).
		Int("chains", len(state.ChainConfigs)).
		Msg("state inference OK: committee membership reconstructs from on-chain state")
	return nil
}

// verifyExecutorInference reconstructs an executor pool from the job specs just
// persisted by ApplyExecutorConfig (appliedDS is that changeset's output store)
// and requires it to match the topology-derived ExecutorPoolInput. This is a pure
// round-trip over the datastore, so it has no on-chain ordering dependency.
func verifyExecutorInference(
	qualifier string,
	topo ccvchangesets.ExecutorPoolInput,
	appliedDS datastore.DataStore,
) error {
	state, _, err := ccvchangesets.ExecutorPoolInputFromState(appliedDS, qualifier)
	if err != nil {
		return fmt.Errorf("executor pool %q: reconstruct from state: %w", qualifier, err)
	}

	if len(state.ChainConfigs) == 0 {
		L.Warn().Str("executor", qualifier).
			Msg("state inference: no executor jobs found in applied datastore; skipping executor check")
		return nil
	}

	if diffs := diffExecutorPool(topo, state); len(diffs) > 0 {
		L.Error().Str("executor", qualifier).Strs("mismatches", diffs).
			Msg("state inference mismatch vs topology-derived executor input")
		return fmt.Errorf("executor pool %q state inference mismatch: %s", qualifier, strings.Join(diffs, "; "))
	}

	L.Info().Str("executor", qualifier).Int("chains", len(state.ChainConfigs)).
		Msg("state inference OK: executor pool reconstructs from persisted job specs")
	return nil
}

// diffCommitteeMembership compares per-chain NOP membership. Only the chains the
// topology-derived input declares for this family are compared (state may surface
// additional chains from other families when family filtering is loose).
func diffCommitteeMembership(topo, state ccvchangesets.CommitteeInput) []string {
	var diffs []string
	for sel, topoMembers := range topo.ChainConfigs {
		stateMembers, ok := state.ChainConfigs[sel]
		if !ok {
			diffs = append(diffs, fmt.Sprintf("chain %d: present in topology, absent on-chain", sel))
			continue
		}
		if d := diffAliasSets(topoMembers.NOPAliases, stateMembers.NOPAliases); d != "" {
			diffs = append(diffs, fmt.Sprintf("chain %d NOPs: %s", sel, d))
		}
	}
	for sel := range state.ChainConfigs {
		if _, ok := topo.ChainConfigs[sel]; !ok {
			diffs = append(diffs, fmt.Sprintf("chain %d: present on-chain, absent in topology", sel))
		}
	}
	return diffs
}

func diffExecutorPool(topo, state ccvchangesets.ExecutorPoolInput) []string {
	var diffs []string
	for sel, topoCfg := range topo.ChainConfigs {
		stateCfg, ok := state.ChainConfigs[sel]
		if !ok {
			diffs = append(diffs, fmt.Sprintf("chain %d: present in topology, absent in job specs", sel))
			continue
		}
		if d := diffAliasSets(topoCfg.NOPAliases, stateCfg.NOPAliases); d != "" {
			diffs = append(diffs, fmt.Sprintf("chain %d pool: %s", sel, d))
		}
		if topoCfg.ExecutionInterval != stateCfg.ExecutionInterval {
			diffs = append(diffs, fmt.Sprintf("chain %d executionInterval: topology=%s state=%s", sel, topoCfg.ExecutionInterval, stateCfg.ExecutionInterval))
		}
	}
	for sel := range state.ChainConfigs {
		if _, ok := topo.ChainConfigs[sel]; !ok {
			diffs = append(diffs, fmt.Sprintf("chain %d: present in job specs, absent in topology", sel))
		}
	}

	// Pool-wide tuning.
	if topo.IndexerQueryLimit != state.IndexerQueryLimit {
		diffs = append(diffs, fmt.Sprintf("indexerQueryLimit: topology=%d state=%d", topo.IndexerQueryLimit, state.IndexerQueryLimit))
	}
	if topo.BackoffDuration != state.BackoffDuration {
		diffs = append(diffs, fmt.Sprintf("backoffDuration: topology=%s state=%s", topo.BackoffDuration, state.BackoffDuration))
	}
	if topo.LookbackWindow != state.LookbackWindow {
		diffs = append(diffs, fmt.Sprintf("lookbackWindow: topology=%s state=%s", topo.LookbackWindow, state.LookbackWindow))
	}
	if topo.ReaderCacheExpiry != state.ReaderCacheExpiry {
		diffs = append(diffs, fmt.Sprintf("readerCacheExpiry: topology=%s state=%s", topo.ReaderCacheExpiry, state.ReaderCacheExpiry))
	}
	if topo.MaxRetryDuration != state.MaxRetryDuration {
		diffs = append(diffs, fmt.Sprintf("maxRetryDuration: topology=%s state=%s", topo.MaxRetryDuration, state.MaxRetryDuration))
	}
	if topo.WorkerCount != state.WorkerCount {
		diffs = append(diffs, fmt.Sprintf("workerCount: topology=%d state=%d", topo.WorkerCount, state.WorkerCount))
	}
	if topo.NtpServer != state.NtpServer {
		diffs = append(diffs, fmt.Sprintf("ntpServer: topology=%q state=%q", topo.NtpServer, state.NtpServer))
	}
	return diffs
}

// diffAliasSets returns "" when the two alias slices hold the same set, otherwise
// a human-readable description of what differs.
func diffAliasSets(a, b []ccvshared.NOPAlias) string {
	sa := sortedAliasStrings(a)
	sb := sortedAliasStrings(b)
	if strings.Join(sa, ",") == strings.Join(sb, ",") {
		return ""
	}
	return fmt.Sprintf("topology=[%s] state=[%s]", strings.Join(sa, ","), strings.Join(sb, ","))
}

func sortedAliasStrings(in []ccvshared.NOPAlias) []string {
	out := make([]string, len(in))
	for i, a := range in {
		out[i] = string(a)
	}
	sort.Strings(out)
	return out
}
