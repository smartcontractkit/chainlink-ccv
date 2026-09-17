package evm

import (
	"fmt"
	"strconv"
	"strings"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
)

// checkDeclaredChainCoverage fails the boot when the bootstrap config's [[chains]] declares an EVM
// chain the mounted EVM config cannot serve. The declaration is the operator's own statement of the
// chains they run, so a chain named there but absent from — or unconvertible in — the EVM config is
// a config mistake, not a choice: without this check the process boots cleanly and the gap surfaces
// only when the first message for that chain arrives.
//
// Every binary that imports this driver fails registry construction when no EVM config is mounted,
// so requiring the file here when EVM chains are declared adds no new requirement — it only fails
// earlier and with the declared chain named.
//
// The check loads the same file the accessor factory will load at job start. The double load is
// deliberate: the file is small, the read is at boot, and reusing one load across the two would
// couple the bootstrapper's config lifecycle to the registry's internals.
func checkDeclaredChainCoverage(chainIDs []string) error {
	if len(chainIDs) == 0 {
		return nil
	}
	cfg, conversion, err := evmconfig.LoadConfigFile(evmconfig.ResolveConfigPath())
	if err != nil {
		return fmt.Errorf("bootstrap config declares EVM chains (%s) but the EVM config cannot be loaded: %w",
			strings.Join(chainIDs, ", "), err)
	}

	// Compare numerically rather than by map key: a selector written in a non-canonical form is
	// ToInfos' error to report, not a coverage gap to invent.
	covered := make(map[uint64]struct{}, len(cfg.Chains))
	for key := range cfg.Chains {
		if selector, err := strconv.ParseUint(key, 10, 64); err == nil {
			covered[selector] = struct{}{}
		}
	}
	failed := make(map[string]string)
	if conversion != nil {
		for _, f := range conversion.FailedChains {
			failed[f.ChainID] = f.Reason
		}
	}

	var missing []string
	for _, id := range chainIDs {
		details, err := chainsel.GetChainDetailsByChainIDAndFamily(id, chainsel.FamilyEVM)
		if err != nil {
			missing = append(missing, fmt.Sprintf("chain %s: the id has no known EVM chain selector — check the [[chains]] entry", id))
			continue
		}
		if _, ok := covered[details.ChainSelector]; ok {
			continue
		}
		if reason, wasSkipped := failed[id]; wasSkipped {
			missing = append(missing, fmt.Sprintf("chain %s (selector %d): the node config's [[EVM]] section for it did not convert: %s",
				id, details.ChainSelector, reason))
			continue
		}
		missing = append(missing, fmt.Sprintf("chain %s (selector %d): the mounted EVM config has no section for it",
			id, details.ChainSelector))
	}
	if len(missing) > 0 {
		return fmt.Errorf("bootstrap config declares EVM chains the mounted EVM config cannot serve: %s. "+
			"Either add each chain to the EVM config (a converted Chainlink node config needs a working "+
			"[[EVM]] + [[EVM.Nodes]] section) or remove it from [[chains]]", strings.Join(missing, "; "))
	}
	return nil
}
