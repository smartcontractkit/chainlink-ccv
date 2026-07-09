package configdoc

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/executor"
)

const modulePath = "github.com/smartcontractkit/chainlink-ccv"

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func newGenerator(t *testing.T) *Generator {
	t.Helper()
	return &Generator{ModuleRoot: repoRoot(t), ModulePath: modulePath}
}

// TestExecutorDoc checks the generated executor doc: comments resolved (including
// across package boundaries), values present, and the shared monitoring config
// rendered as a stub rather than an inlined table.
func TestExecutorDoc(t *testing.T) {
	out, err := newGenerator(t).Render(Targets[0])
	require.NoError(t, err)

	// comments attached to fields, with the leading token rewritten to the TOML key
	require.Contains(t, out, "# indexer_address is the list of indexer URLs")
	require.Contains(t, out, "# worker_count is the number of concurrent workers")
	// cross-package embedded field comment
	require.Contains(t, out, "# off_ramp_address is the address of the OffRamp contract")

	// values from the documented instance
	require.Contains(t, out, `indexer_address = ["http://indexer-1:8080", "http://indexer-2:8080"]`)
	require.Contains(t, out, `ntp_server = "time.google.com"`)
	require.Contains(t, out, "[chain_configuration.1]")

	// monitoring is inlined (no shared-stub mechanism), with its deprecation note
	// and its own fields' comments resolved from the common/monitoring package
	require.Contains(t, out, "# Monitoring is DEPRECATED")
	require.Contains(t, out, "[Monitoring.Beholder]")
	require.Contains(t, out, "# LogLevel specifies the logging level")

	// top-level fields are separated by a blank line
	require.Contains(t, out, "indexer_address = [\"http://indexer-1:8080\", \"http://indexer-2:8080\"]\n\n#")
}

// TestExecutorDocDecodes proves the generated doc is a loadable config: it decodes
// through BurntSushi (strict) and passes the executor's real normalization, and
// the decoded config matches the documented instance (freshness oracle).
func TestExecutorDocDecodes(t *testing.T) {
	out, err := newGenerator(t).Render(Targets[0])
	require.NoError(t, err)

	var cfg executor.Configuration
	md, err := toml.Decode(out, &cfg)
	require.NoError(t, err, "documented TOML must decode")
	require.Empty(t, md.Undecoded(), "documented TOML has keys not on the struct")

	got, err := cfg.GetNormalizedConfig()
	require.NoError(t, err, "documented config must pass validation + normalization")
	require.Equal(t, executorDocInstance(), got)
}

// TestConfigDocsFresh regenerates every registered doc and asserts it matches the
// committed file. Generation is deterministic and struct-driven, so this diff is
// the freshness + completeness guarantee.
func TestConfigDocsFresh(t *testing.T) {
	g := newGenerator(t)
	for _, target := range Targets {
		t.Run(target.Name, func(t *testing.T) {
			out, err := g.Render(target)
			require.NoError(t, err)

			path := filepath.Join(g.ModuleRoot, "docs", "config", filepath.FromSlash(target.Out))
			committed, err := os.ReadFile(path)
			require.NoError(t, err, "missing committed doc %s; run: just config-docs", target.Out)
			require.Equal(t, string(committed), out, "%s is out of date; run: just config-docs", target.Out)
		})
	}
}
