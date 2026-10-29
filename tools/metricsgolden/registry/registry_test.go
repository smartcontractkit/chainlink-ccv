package registry_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/smartcontractkit/chainlink-ccv/common/metrics/metricsgolden"
	"github.com/smartcontractkit/chainlink-ccv/common/metrics/metricstest"
	"github.com/smartcontractkit/chainlink-ccv/tools/metricsgolden/registry"
)

// goldenPath is the golden file, relative to this package.
const goldenPath = "testdata/metrics.golden.json"

// TestMetricsGolden fails when a metric or label of a registered target changes.
func TestMetricsGolden(t *testing.T) {
	got := make(metricsgolden.File, len(registry.Targets))
	for _, tgt := range registry.Targets {
		t.Run(tgt.Name, func(t *testing.T) {
			var views []sdkmetric.View
			if tgt.Views != nil {
				views = tgt.Views()
			}
			got[tgt.Name] = metricstest.Snapshot(t, views, func() { tgt.Exercise(t) }, tgt.Unrecorded...)
		})
	}
	metricstest.AssertGolden(t, goldenPath, got)
}

// TestAllMetricPackagesRegistered fails when a package calls beholder.GetMeter() but has no Target.
func TestAllMetricPackagesRegistered(t *testing.T) {
	root := moduleRoot(t)
	registered := make([]string, 0, len(registry.Targets))
	for _, tgt := range registry.Targets {
		registered = append(registered, tgt.Package)
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" || isModule(path)) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return err
		}
		if !strings.Contains(string(b), "beholder.GetMeter()") {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		if !slices.Contains(registered, filepath.ToSlash(rel)) {
			t.Errorf("%s calls beholder.GetMeter() but has no Target in tools/metricsgolden/registry", rel)
		}
		return nil
	})
	require.NoError(t, err)
}

// moduleRoot returns the directory of the go.mod that contains this package.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for !isModule(dir) {
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "go.mod not found")
		dir = parent
	}
	return dir
}

func isModule(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "go.mod"))
	return err == nil
}
