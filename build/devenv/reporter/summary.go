package reporter

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// printSummary writes a human-readable summary of the environment to out.
// outTomlPath is the path to the env-out.toml produced by Store(); an empty
// string or a non-existent file is handled gracefully.
func printSummary(out io.Writer, outTomlPath string) {
	if outTomlPath == "" {
		return
	}

	abs, err := resolveTomlPath(outTomlPath)
	if err != nil {
		fmt.Fprintf(out, "\nenv output: %s (not found)\n", outTomlPath)
		return
	}

	var raw map[string]any
	if _, err := toml.DecodeFile(abs, &raw); err != nil {
		fmt.Fprintf(out, "\nenv output: %s (parse error: %v)\n", abs, err)
		return
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "env output: %s\n", abs)
	fmt.Fprintln(out, strings.Repeat("─", 60))

	summarizeBlockchains(out, raw)
	summarizeAggregators(out, raw)
	summarizeVerifiers(out, raw)
	summarizeIndexers(out, raw)
	summarizeExecutors(out, raw)
	summarizeFake(out, raw)
}

func resolveTomlPath(path string) (string, error) {
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	// The Store function writes relative to DefaultConfigDir (".").
	// Check the current working directory.
	abs := "./" + path
	if _, err := os.Stat(abs); err == nil {
		return abs, nil
	}
	return "", fmt.Errorf("not found")
}

// ── section helpers ───────────────────────────────────────────────────────────

func summarizeBlockchains(out io.Writer, raw map[string]any) {
	bcs := toSlice(raw["blockchains"])
	if len(bcs) == 0 {
		return
	}
	fmt.Fprintf(out, "chains (%d):\n", len(bcs))
	for _, item := range bcs {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		chainID := strField(m, "chain_id")
		o := subMap(m, "out")
		nodes := toSlice(o["nodes"])
		for _, n := range nodes {
			nm, ok := n.(map[string]any)
			if !ok {
				continue
			}
			http := strField(nm, "http_url")
			ws := strField(nm, "ws_url")
			fmt.Fprintf(out, "  chain %s  http: %s  ws: %s\n", chainID, http, ws)
		}
	}
}

func summarizeAggregators(out io.Writer, raw map[string]any) {
	aggs := toSlice(raw["aggregators"])
	if len(aggs) == 0 {
		return
	}
	fmt.Fprintf(out, "aggregators (%d):\n", len(aggs))
	for _, item := range aggs {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		o := subMap(m, "out")
		name := strField(m, "committee_name")
		ext := strField(o, "external_https_url")
		if ext == "" {
			ext = strField(o, "external_http_url")
		}
		fmt.Fprintf(out, "  %s  %s\n", name, ext)
	}
}

func summarizeVerifiers(out io.Writer, raw map[string]any) {
	vs := toSlice(raw["verifiers"])
	if len(vs) == 0 {
		return
	}
	fmt.Fprintf(out, "verifiers (%d)\n", len(vs))
}

func summarizeIndexers(out io.Writer, raw map[string]any) {
	idxs := toSlice(raw["indexer"])
	if len(idxs) == 0 {
		return
	}
	fmt.Fprintf(out, "indexers (%d):\n", len(idxs))
	for _, item := range idxs {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		o := subMap(m, "out")
		url := strField(o, "http_url")
		fmt.Fprintf(out, "  %s\n", url)
	}
}

func summarizeExecutors(out io.Writer, raw map[string]any) {
	exs := toSlice(raw["executor"])
	if len(exs) == 0 {
		return
	}
	fmt.Fprintf(out, "executors (%d):\n", len(exs))
	for _, item := range exs {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := strField(m, "container_name")
		o := subMap(m, "out")
		url := strField(o, "http_url")
		fmt.Fprintf(out, "  %s  %s\n", name, url)
	}
}

func summarizeFake(out io.Writer, raw map[string]any) {
	f, ok := raw["fake"].(map[string]any)
	if !ok {
		return
	}
	o := subMap(f, "out")
	url := strField(o, "http_url")
	if url != "" {
		fmt.Fprintf(out, "fake: %s\n", url)
	}
}

// ── TOML decode helpers ───────────────────────────────────────────────────────

// toSlice normalises a TOML array-of-tables ([]any) or a single table
// (map[string]any) into a []any.
func toSlice(v any) []any {
	if v == nil {
		return nil
	}
	if s, ok := v.([]any); ok {
		return s
	}
	if m, ok := v.(map[string]any); ok {
		return []any{m}
	}
	return nil
}

func subMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	sub, _ := m[key].(map[string]any)
	return sub
}

func strField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}
