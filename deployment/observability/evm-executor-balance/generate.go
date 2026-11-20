package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const runbookURL = "https://github.com/smartcontractkit/chainlink-ccv/blob/main/docs/runbooks/evm-executor-balance.md"

var evmAddressPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

type thresholdFile struct {
	Source string                    `json:"source"`
	Metric string                    `json:"metric"`
	Chains map[string]chainThreshold `json:"chains"`
}

type chainThreshold struct {
	Name    string      `json:"name"`
	Symbol  string      `json:"symbol"`
	Minimum json.Number `json:"minimum"`
}

type inventoryFile struct {
	Chains []inventoryEntry `json:"chains"`
}

type inventoryEntry struct {
	ChainID string `json:"chain_id"`
	Account string `json:"account"`
}

type ruleFile struct {
	Groups []ruleGroup `json:"groups"`
}

type ruleGroup struct {
	Name     string `json:"name"`
	Interval string `json:"interval"`
	Rules    []rule `json:"rules"`
}

type rule struct {
	Alert       string            `json:"alert"`
	Expr        string            `json:"expr"`
	For         string            `json:"for"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

func decodeJSONFile(path string, destination any) error {
	data, err := os.ReadFile(path) //nolint:gosec // Operator-selected public inventory and threshold files.
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("decode %s: multiple JSON values", path)
	}
	return nil
}

func validateThresholds(thresholds thresholdFile) error {
	if thresholds.Metric != "node_balance" {
		return fmt.Errorf("threshold metric must be node_balance, got %q", thresholds.Metric)
	}
	if len(thresholds.Chains) == 0 {
		return fmt.Errorf("threshold file has no chains")
	}
	for chainID, threshold := range thresholds.Chains {
		minimum, err := threshold.Minimum.Float64()
		if err != nil || minimum <= 0 {
			return fmt.Errorf("chain %s has invalid minimum %q", chainID, threshold.Minimum)
		}
		if threshold.Name == "" || threshold.Symbol == "" {
			return fmt.Errorf("chain %s must have a name and symbol", chainID)
		}
	}
	return nil
}

func generateRules(inventory inventoryFile, thresholds thresholdFile) (ruleFile, error) {
	if err := validateThresholds(thresholds); err != nil {
		return ruleFile{}, err
	}
	if len(inventory.Chains) == 0 {
		return ruleFile{}, fmt.Errorf("inventory has no assigned chains")
	}
	entries := append([]inventoryEntry(nil), inventory.Chains...)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ChainID == entries[j].ChainID {
			return entries[i].Account < entries[j].Account
		}
		return entries[i].ChainID < entries[j].ChainID
	})
	groups := []ruleGroup{
		{Name: "ccv-evm-executor-balance-low", Interval: "30s"},
		{Name: "ccv-evm-executor-balance-absent", Interval: "30s"},
		{Name: "ccv-evm-executor-balance-stale", Interval: "30s"},
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		selectorValue, err := strconv.ParseUint(entry.ChainID, 10, 64)
		if err != nil || strconv.FormatUint(selectorValue, 10) != entry.ChainID {
			return ruleFile{}, fmt.Errorf("chain_id %q must be a canonical unsigned decimal", entry.ChainID)
		}
		if !evmAddressPattern.MatchString(entry.Account) {
			return ruleFile{}, fmt.Errorf("account %q on chain %s is not a 20-byte EVM address", entry.Account, entry.ChainID)
		}
		key := entry.ChainID + "/" + strings.ToLower(entry.Account)
		if _, ok := seen[key]; ok {
			return ruleFile{}, fmt.Errorf("duplicate inventory entry %s", key)
		}
		seen[key] = struct{}{}
		threshold, ok := thresholds.Chains[entry.ChainID]
		if !ok {
			return ruleFile{}, fmt.Errorf("chain %s has no approved balance threshold; update the reviewed threshold manifest before alerting", entry.ChainID)
		}
		selector := fmt.Sprintf("node_balance{account=%s,chainID=%s,chainFamily=\"EVM\"}",
			strconv.Quote(entry.Account), strconv.Quote(entry.ChainID))
		commonLabels := map[string]string{
			"service":  "chainlink-ccv-executor",
			"runbook":  runbookURL,
			"chain_id": entry.ChainID,
		}
		lowLabels := cloneLabels(commonLabels)
		lowLabels["severity"] = "critical"
		lowLabels["threshold"] = threshold.Minimum.String()
		lowLabels["threshold_unit"] = threshold.Symbol
		groups[0].Rules = append(groups[0].Rules, rule{
			Alert:  "CCVExecutorBalanceLow",
			Expr:   selector + " < " + threshold.Minimum.String(),
			For:    "15m",
			Labels: lowLabels,
			Annotations: map[string]string{
				"summary":     fmt.Sprintf("Executor transmitter balance is low on %s (%s)", threshold.Name, entry.ChainID),
				"description": fmt.Sprintf("Account %s has {{ $value }} %s; required minimum is %s %s.", entry.Account, threshold.Symbol, threshold.Minimum, threshold.Symbol),
			},
		})
		absentLabels := cloneLabels(commonLabels)
		absentLabels["severity"] = "critical"
		groups[1].Rules = append(groups[1].Rules, rule{
			Alert:  "CCVExecutorBalanceAbsent",
			Expr:   "absent(" + selector + ")",
			For:    "10m",
			Labels: absentLabels,
			Annotations: map[string]string{
				"summary":     fmt.Sprintf("Executor balance series is absent on %s (%s)", threshold.Name, entry.ChainID),
				"description": fmt.Sprintf("No node_balance sample exists for account %s. Check Beholder, the sidecar scrape, and BalanceMonitor.Enabled.", entry.Account),
			},
		})
		staleLabels := cloneLabels(commonLabels)
		staleLabels["severity"] = "warning"
		groups[2].Rules = append(groups[2].Rules, rule{
			Alert:  "CCVExecutorBalanceStale",
			Expr:   "(time() - timestamp(" + selector + ")) > 600",
			For:    "5m",
			Labels: staleLabels,
			Annotations: map[string]string{
				"summary":     fmt.Sprintf("Executor balance series is stale on %s (%s)", threshold.Name, entry.ChainID),
				"description": fmt.Sprintf("The newest sample for account %s is over ten minutes old; read failures may leave no reliable current value.", entry.Account),
			},
		})
	}
	return ruleFile{Groups: groups}, nil
}

func cloneLabels(labels map[string]string) map[string]string {
	cloned := make(map[string]string, len(labels)+3)
	maps.Copy(cloned, labels)
	return cloned
}

func run(inventoryPath, thresholdsPath, outputPath string) error {
	var inventory inventoryFile
	if err := decodeJSONFile(inventoryPath, &inventory); err != nil {
		return err
	}
	var thresholds thresholdFile
	if err := decodeJSONFile(thresholdsPath, &thresholds); err != nil {
		return err
	}
	rules, err := generateRules(inventory, thresholds)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(outputPath, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", outputPath, err)
	}
	return nil
}

func main() {
	inventoryPath := flag.String("inventory", "", "path to assigned chain/account inventory JSON")
	thresholdsPath := flag.String("thresholds", "", "path to reviewed balance thresholds JSON")
	outputPath := flag.String("output", "", "path for the generated Prometheus rule file")
	flag.Parse()
	if *inventoryPath == "" || *thresholdsPath == "" || *outputPath == "" {
		_, _ = fmt.Fprintln(os.Stderr, "-inventory, -thresholds, and -output are required")
		os.Exit(2)
	}
	if err := run(*inventoryPath, *thresholdsPath, *outputPath); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "generate balance alerts: %v\n", err)
		os.Exit(1)
	}
}
