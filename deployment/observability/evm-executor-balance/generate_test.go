package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

const testAccount = "0x0000000000000000000000000000000000000001"

func testThresholds() thresholdFile {
	return thresholdFile{
		Source: "test",
		Metric: "node_balance",
		Chains: map[string]chainThreshold{
			"1":    {Name: "Ethereum", Symbol: "ETH", Minimum: json.Number("3")},
			"5000": {Name: "Mantle", Symbol: "MNT", Minimum: json.Number("1600")},
		},
	}
}

func TestGenerateRules(t *testing.T) {
	rules, err := generateRules(inventoryFile{Chains: []inventoryEntry{
		{ChainID: "5000", Account: testAccount},
		{ChainID: "1", Account: testAccount},
	}}, testThresholds())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules.Groups) != 3 {
		t.Fatalf("got %d groups, want 3", len(rules.Groups))
	}
	for _, group := range rules.Groups {
		if len(group.Rules) != 2 {
			t.Fatalf("group %s has %d rules, want 2", group.Name, len(group.Rules))
		}
	}
	low := rules.Groups[0].Rules[0]
	if low.Expr != `node_balance{account="0x0000000000000000000000000000000000000001",chainID="1",chainFamily="EVM"} < 3` {
		t.Fatalf("unexpected low expression: %s", low.Expr)
	}
	if low.Labels["threshold"] != "3" || low.Labels["threshold_unit"] != "ETH" {
		t.Fatalf("missing threshold labels: %#v", low.Labels)
	}
	absent := rules.Groups[1].Rules[0]
	if !strings.HasPrefix(absent.Expr, "absent(node_balance{") {
		t.Fatalf("unexpected absent expression: %s", absent.Expr)
	}
	stale := rules.Groups[2].Rules[0]
	if !strings.Contains(stale.Expr, "timestamp(node_balance{") || !strings.Contains(stale.Expr, "> 600") {
		t.Fatalf("unexpected stale expression: %s", stale.Expr)
	}
	if _, err := json.Marshal(rules); err != nil {
		t.Fatalf("generated rules are not valid JSON/YAML: %v", err)
	}
}

func TestGenerateRulesFailsClosed(t *testing.T) {
	tests := []struct {
		name       string
		inventory  inventoryFile
		thresholds thresholdFile
		want       string
	}{
		{name: "empty inventory", thresholds: testThresholds(), want: "no assigned chains"},
		{name: "unknown chain", inventory: inventoryFile{Chains: []inventoryEntry{{ChainID: "2", Account: testAccount}}}, thresholds: testThresholds(), want: "no approved balance threshold"},
		{name: "invalid account", inventory: inventoryFile{Chains: []inventoryEntry{{ChainID: "1", Account: "not-an-address"}}}, thresholds: testThresholds(), want: "not a 20-byte EVM address"},
		{name: "noncanonical chain", inventory: inventoryFile{Chains: []inventoryEntry{{ChainID: "01", Account: testAccount}}}, thresholds: testThresholds(), want: "canonical unsigned decimal"},
		{name: "duplicate account", inventory: inventoryFile{Chains: []inventoryEntry{{ChainID: "1", Account: testAccount}, {ChainID: "1", Account: "0x0000000000000000000000000000000000000001"}}}, thresholds: testThresholds(), want: "duplicate inventory entry"},
		{name: "wrong metric", inventory: inventoryFile{Chains: []inventoryEntry{{ChainID: "1", Account: testAccount}}}, thresholds: thresholdFile{Metric: "eth_balance"}, want: "must be node_balance"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := generateRules(test.inventory, test.thresholds)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got error %v, want text %q", err, test.want)
			}
		})
	}
}

func TestGenerateRulesFor51Chains(t *testing.T) {
	var thresholds thresholdFile
	if err := decodeJSONFile("thresholds.json", &thresholds); err != nil {
		t.Fatal(err)
	}
	chainIDs := make([]string, 0, len(thresholds.Chains))
	for chainID := range thresholds.Chains {
		chainIDs = append(chainIDs, chainID)
	}
	sort.Strings(chainIDs)
	if len(chainIDs) < 51 {
		t.Fatalf("threshold manifest has only %d chains", len(chainIDs))
	}
	inventory := inventoryFile{Chains: make([]inventoryEntry, 51)}
	for i := range inventory.Chains {
		inventory.Chains[i] = inventoryEntry{ChainID: chainIDs[i], Account: testAccount}
	}
	rules, err := generateRules(inventory, thresholds)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range rules.Groups {
		if len(group.Rules) != 51 {
			t.Fatalf("group %s has %d rules, want 51", group.Name, len(group.Rules))
		}
		for _, rule := range group.Rules {
			if strings.Contains(rule.Expr, "_bucket") || strings.Contains(rule.Expr, "histogram_") {
				t.Fatalf("rule depends on a histogram: %s", rule.Expr)
			}
		}
	}
	if got := len(inventory.Chains); got != 51 {
		t.Fatalf("raw balance series cardinality %d, want 51", got)
	}
}

func TestRunWritesRuleFile(t *testing.T) {
	directory := t.TempDir()
	inventoryPath := directory + "/inventory.json"
	outputPath := directory + "/alerts.yaml"
	inventory := `{"chains":[{"chain_id":"1","account":"0x0000000000000000000000000000000000000001"}]}`
	if err := writeTestFile(inventoryPath, inventory); err != nil {
		t.Fatal(err)
	}
	if err := run(inventoryPath, "thresholds.json", outputPath); err != nil {
		t.Fatal(err)
	}
	var rules ruleFile
	if err := decodeJSONFile(outputPath, &rules); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(len(rules.Groups)); got != "3" {
		t.Fatalf("got %s groups", got)
	}
}

func writeTestFile(path, contents string) error {
	return os.WriteFile(path, []byte(contents), 0o600)
}

func TestObservabilityAssets(t *testing.T) {
	dashboardData, err := os.ReadFile("dashboard.json")
	if err != nil {
		t.Fatal(err)
	}
	var dashboard struct {
		Panels []struct {
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(dashboardData, &dashboard); err != nil {
		t.Fatalf("invalid dashboard JSON: %v", err)
	}
	queries := 0
	for _, panel := range dashboard.Panels {
		for _, target := range panel.Targets {
			if target.Expr == "" {
				continue
			}
			queries++
			if !strings.Contains(target.Expr, "node_balance") {
				t.Fatalf("unexpected non-balance query: %s", target.Expr)
			}
			if strings.Contains(target.Expr, "_bucket") || strings.Contains(target.Expr, "histogram_") {
				t.Fatalf("dashboard depends on a histogram: %s", target.Expr)
			}
		}
	}
	if queries < 4 {
		t.Fatalf("dashboard has only %d queries", queries)
	}
	devenvDashboard, err := os.ReadFile("../../../build/devenv/dashboards/evm_executor_balance.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dashboardData, devenvDashboard) {
		t.Fatal("devenv dashboard differs from the production asset")
	}

	var example ruleFile
	if err := decodeJSONFile("alerts.example.yaml", &example); err != nil {
		t.Fatalf("example alert file is not valid JSON-compatible YAML: %v", err)
	}
	if len(example.Groups) != 3 || len(example.Groups[0].Rules) != 2 {
		t.Fatalf("unexpected example alert structure: %#v", example.Groups)
	}
}
