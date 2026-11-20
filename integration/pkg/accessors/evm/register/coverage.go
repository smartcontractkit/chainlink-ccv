package register

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
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
// CheckDeclaredChainInventory enforces exact bootstrap/EVM reconciliation for standalone JD binaries.
func CheckDeclaredChainInventory(registrations []bootstrap.ChainRegistration) error {
	declarations := make([]evmconfig.ChainDeclaration, 0, len(registrations))
	evmChains := 0
	for _, registration := range registrations {
		declarations = append(declarations, evmconfig.ChainDeclaration{Type: registration.Type, ID: registration.ID})
		if strings.EqualFold(registration.Type, chainsel.FamilyEVM) {
			evmChains++
		}
	}
	if evmChains == 0 {
		report, err := evmconfig.ReconcileChainInventory(&evmconfig.Config{}, nil, declarations)
		if err != nil {
			return err
		}
		return report.Err()
	}

	cfg, conversion, err := evmconfig.LoadConfigFile(evmconfig.ResolveConfigPath())
	if err != nil {
		return fmt.Errorf("standalone EVM chain inventory cannot load the EVM config: %w", err)
	}
	chainIDs := make([]string, 0, evmChains)
	for _, declaration := range declarations {
		if strings.EqualFold(declaration.Type, chainsel.FamilyEVM) {
			chainIDs = append(chainIDs, declaration.ID)
		}
	}
	coverageErr := checkDeclaredChainCoverageConfig(chainIDs, cfg, conversion)
	report, err := evmconfig.ReconcileChainInventory(cfg, conversion, declarations)
	if err != nil {
		return errors.Join(coverageErr, err)
	}
	return errors.Join(coverageErr, report.Err())
}

func checkDeclaredChainCoverage(chainIDs []string) error {
	if len(chainIDs) == 0 {
		return nil
	}
	cfg, conversion, err := evmconfig.LoadConfigFile(evmconfig.ResolveConfigPath())
	if err != nil {
		return fmt.Errorf("bootstrap config declares EVM chains (%s) but the EVM config cannot be loaded: %w",
			strings.Join(chainIDs, ", "), err)
	}
	return checkDeclaredChainCoverageConfig(chainIDs, cfg, conversion)
}

func checkDeclaredChainCoverageConfig(chainIDs []string, cfg *evmconfig.Config, conversion *evmconfig.Conversion) error {
	infos, err := cfg.ToInfos()
	if err != nil {
		return fmt.Errorf("bootstrap config declares EVM chains (%s) but the EVM config is invalid: %w",
			strings.Join(chainIDs, ", "), err)
	}
	failed := make(map[string]string)
	disabled := make(map[string]struct{})
	if conversion != nil {
		for _, f := range conversion.FailedChains {
			failed[f.ChainID] = f.Reason
		}
		for _, id := range conversion.DisabledChains {
			disabled[id] = struct{}{}
		}
	}

	var missing []string
	for _, id := range chainIDs {
		details, err := chainsel.GetChainDetailsByChainIDAndFamily(id, chainsel.FamilyEVM)
		if err != nil {
			missing = append(missing, fmt.Sprintf("chain %s: the id has no known EVM chain selector — check the [[chains]] entry", id))
			continue
		}
		if info, ok := infos[strconv.FormatUint(details.ChainSelector, 10)]; ok {
			// A section being present is not the same as it being servable: one with no nodes, or
			// one the chainlink-evm validator rejects, decodes fine and fails only when the first
			// accessor is built at job start. Building it here is that same work — no network
			// calls — so the boot names the declared chain instead of a job failing later.
			if _, buildErr := evmconfig.BuildChainlinkEVMTOML(info); buildErr != nil {
				missing = append(missing, fmt.Sprintf(
					"chain %s (selector %d): the mounted EVM config has a section for it that cannot serve it: %v",
					id, details.ChainSelector, buildErr))
			}
			continue
		}
		// A chain the operator disabled explicitly is a choice, not a gap: the node was not
		// serving it either. The conversion already logged the skip at warn, and the declaration
		// still registers the signing key for it in JD — failing the boot here would crash-loop a
		// legitimate state (e.g. a chain disabled after an incident, pending remediation).
		if _, isDisabled := disabled[id]; isDisabled {
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
