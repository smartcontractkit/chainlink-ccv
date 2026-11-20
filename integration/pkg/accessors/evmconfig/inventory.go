package evmconfig

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	chainsel "github.com/smartcontractkit/chain-selectors"
)

// ChainDeclaration is the non-secret chain identity from a bootstrap [[chains]] entry.
type ChainDeclaration struct {
	Type string
	ID   string
}

// ChainInventoryReport compares bootstrap signing declarations with the converted EVM chain inventory.
type ChainInventoryReport struct {
	Empty                   bool     `json:"empty"`
	DeclaredChains          []string `json:"declared_evm_chain_ids,omitempty"`
	ConfiguredChains        []string `json:"configured_evm_chain_ids,omitempty"`
	MissingDeclarations     []string `json:"missing_declarations,omitempty"`
	ExtraDeclarations       []string `json:"extra_declarations,omitempty"`
	DuplicateDeclarations   []string `json:"duplicate_declarations,omitempty"`
	UnsupportedDeclarations []string `json:"unsupported_declarations,omitempty"`
}

func (r ChainInventoryReport) Err() error {
	var errs []error
	if r.Empty {
		errs = append(errs, errors.New("standalone EVM chain inventory is empty: bootstrap [[chains]] must declare at least one EVM chain"))
	}
	if len(r.MissingDeclarations) > 0 {
		errs = append(errs, fmt.Errorf("missing bootstrap [[chains]] declarations for configured EVM chain IDs: %s",
			strings.Join(r.MissingDeclarations, ", ")))
	}
	if len(r.ExtraDeclarations) > 0 {
		errs = append(errs, fmt.Errorf("extra bootstrap [[chains]] declarations absent from the EVM config: %s",
			strings.Join(r.ExtraDeclarations, ", ")))
	}
	if len(r.DuplicateDeclarations) > 0 {
		errs = append(errs, fmt.Errorf("duplicate bootstrap [[chains]] declarations for EVM chain IDs: %s",
			strings.Join(r.DuplicateDeclarations, ", ")))
	}
	if len(r.UnsupportedDeclarations) > 0 {
		errs = append(errs, fmt.Errorf("unsupported bootstrap chain declarations: %s",
			strings.Join(r.UnsupportedDeclarations, ", ")))
	}
	return errors.Join(errs...)
}

// ReconcileChainInventory requires one declaration for every active or explicitly disabled EVM chain.
func ReconcileChainInventory(cfg *Config, conversion *Conversion, declarations []ChainDeclaration) (*ChainInventoryReport, error) {
	infos, err := cfg.ToInfos()
	if err != nil {
		return nil, fmt.Errorf("cannot reconcile bootstrap declarations with the EVM config: %w", err)
	}
	expected := make(map[string]struct{}, len(infos))
	for selector, info := range infos {
		if info.Family != chainsel.FamilyEVM {
			return nil, fmt.Errorf("chain selector %s belongs to family %s, not EVM", selector, info.Family)
		}
		expected[info.ChainID] = struct{}{}
	}
	if conversion != nil {
		for _, chainID := range conversion.DisabledChains {
			expected[chainID] = struct{}{}
		}
	}

	report := &ChainInventoryReport{Empty: true, ConfiguredChains: sortedChainIDs(expected)}
	declared := make(map[string]struct{}, len(declarations))
	duplicates := make(map[string]struct{})
	seen := make(map[string]struct{}, len(declarations))
	failed := make(map[string]string)
	if conversion != nil {
		for _, failure := range conversion.FailedChains {
			failed[failure.ChainID] = failure.Reason
		}
	}
	for _, declaration := range declarations {
		if !strings.EqualFold(declaration.Type, chainsel.FamilyEVM) {
			report.UnsupportedDeclarations = append(report.UnsupportedDeclarations,
				fmt.Sprintf("%s/%s (standalone EVM binaries accept only type = \"EVM\")", declaration.Type, declaration.ID))
			continue
		}
		report.Empty = false
		chainID := declaration.ID
		if _, ok := seen[chainID]; ok {
			duplicates[chainID] = struct{}{}
		}
		seen[chainID] = struct{}{}
		declared[chainID] = struct{}{}
		if _, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM); err != nil {
			report.UnsupportedDeclarations = append(report.UnsupportedDeclarations,
				fmt.Sprintf("EVM/%s (unknown EVM chain ID)", chainID))
			continue
		}
		if reason, ok := failed[chainID]; ok {
			report.UnsupportedDeclarations = append(report.UnsupportedDeclarations,
				fmt.Sprintf("EVM/%s (EVM config cannot serve it: %s)", chainID, reason))
			continue
		}
		if _, ok := expected[chainID]; !ok {
			report.ExtraDeclarations = append(report.ExtraDeclarations, chainID)
		}
	}
	for chainID := range expected {
		if _, ok := declared[chainID]; !ok {
			report.MissingDeclarations = append(report.MissingDeclarations, chainID)
		}
	}
	report.DeclaredChains = sortedChainIDs(declared)
	report.DuplicateDeclarations = sortedChainIDs(duplicates)
	sort.Strings(report.MissingDeclarations)
	sort.Strings(report.ExtraDeclarations)
	sort.Strings(report.UnsupportedDeclarations)
	return report, nil
}

func sortedChainIDs(ids map[string]struct{}) []string {
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
