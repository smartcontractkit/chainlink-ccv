// Package metricsgolden defines the metrics golden file format and the add-only compare rules.
// Dashboards and alerts depend on these metrics, so a change may add metrics and labels but not remove them.
package metricsgolden

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
)

// File is the content of a golden file: the metrics of each target, by target name.
type File map[string][]Metric

// Metric describes one OTel instrument and the attribute keys it records.
type Metric struct {
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Unit        string    `json:"unit"`
	Description string    `json:"description"`
	Buckets     []float64 `json:"buckets,omitempty"`
	Labels      []string  `json:"labels"`
}

// Normalize sorts the metrics by name and the labels of each metric, so that the file content is stable.
func Normalize(metrics []Metric) []Metric {
	out := slices.Clone(metrics)
	for i := range out {
		labels := slices.Clone(out[i].Labels)
		if labels == nil {
			labels = []string{}
		}
		sort.Strings(labels)
		out[i].Labels = slices.Compact(labels)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Marshal returns the golden file content. JSON object keys are sorted, so the output is stable.
func Marshal(f File) ([]byte, error) {
	normalized := make(File, len(f))
	for target, metrics := range f {
		normalized[target] = Normalize(metrics)
	}
	b, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Parse decodes golden file content.
func Parse(b []byte) (File, error) {
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return f, nil
}

// Load reads a golden file.
func Load(path string) (File, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	f, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return f, nil
}

// Violation is a change from base to head that can break a consumer of the metric.
type Violation struct {
	Target string
	Metric string
	Reason string
}

func (v Violation) String() string {
	return fmt.Sprintf("%s: %s: %s", v.Target, v.Metric, v.Reason)
}

// Compare returns the changes from base to head that remove or change a metric.
// New targets, new metrics, new labels and description changes are allowed.
func Compare(base, head File) []Violation {
	targets := make([]string, 0, len(base))
	for target := range base {
		targets = append(targets, target)
	}
	sort.Strings(targets)

	var violations []Violation
	for _, target := range targets {
		for _, v := range compareMetrics(base[target], head[target]) {
			v.Target = target
			violations = append(violations, v)
		}
	}
	return violations
}

func compareMetrics(base, head []Metric) []Violation {
	headByName := make(map[string]Metric, len(head))
	for _, m := range head {
		headByName[m.Name] = m
	}

	var violations []Violation
	for _, b := range Normalize(base) {
		h, ok := headByName[b.Name]
		if !ok {
			violations = append(violations, Violation{Metric: b.Name, Reason: "metric removed"})
			continue
		}
		if b.Kind != h.Kind {
			violations = append(violations, Violation{Metric: b.Name, Reason: fmt.Sprintf("kind changed from %s to %s", b.Kind, h.Kind)})
		}
		if b.Unit != h.Unit {
			violations = append(violations, Violation{Metric: b.Name, Reason: fmt.Sprintf("unit changed from %q to %q", b.Unit, h.Unit)})
		}
		if !slices.Equal(b.Buckets, h.Buckets) {
			violations = append(violations, Violation{Metric: b.Name, Reason: fmt.Sprintf("buckets changed from %v to %v", b.Buckets, h.Buckets)})
		}
		for _, label := range b.Labels {
			if !slices.Contains(h.Labels, label) {
				violations = append(violations, Violation{Metric: b.Name, Reason: fmt.Sprintf("label %q removed", label)})
			}
		}
	}
	return violations
}
