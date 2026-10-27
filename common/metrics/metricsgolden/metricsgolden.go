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

// FileName is the name of a golden file in a testdata directory.
const FileName = "metrics.golden.json"

// Metric describes one OTel instrument and the attribute keys it records.
type Metric struct {
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Unit        string    `json:"unit"`
	Description string    `json:"description"`
	Buckets     []float64 `json:"buckets,omitempty"`
	Labels      []string  `json:"labels"`
}

// Normalize sorts the metrics by name and the labels of each metric, so that
// the file content is stable.
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

// Marshal returns the golden file content for the metrics.
func Marshal(metrics []Metric) ([]byte, error) {
	b, err := json.MarshalIndent(Normalize(metrics), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Load reads a golden file.
func Load(path string) ([]Metric, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var metrics []Metric
	if err := json.Unmarshal(b, &metrics); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return metrics, nil
}

// Violation is a change from base to head that can break a consumer of the metric.
type Violation struct {
	Metric string
	Reason string
}

func (v Violation) String() string {
	return fmt.Sprintf("%s: %s", v.Metric, v.Reason)
}

// Compare returns the changes from base to head that remove or change a metric.
// New metrics, new labels and description changes are allowed.
func Compare(base, head []Metric) []Violation {
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
