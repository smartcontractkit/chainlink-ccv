package registry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/tools/configdoc"
)

// newGenerator builds a Generator by auto-detecting the enclosing module from the
// test's working directory (the package dir), so it works regardless of where the
// repo is checked out.
func newGenerator(t *testing.T) *configdoc.Generator {
	t.Helper()
	cwd, err := os.Getwd()
	require.NoError(t, err)
	g, err := configdoc.NewGenerator(cwd)
	require.NoError(t, err)
	return g
}

func docsDir(g *configdoc.Generator) string {
	return filepath.Join(g.ModuleRoot, "docs", "config")
}

// findTarget returns the registered target with the given Out path.
func findTarget(t *testing.T, out string) configdoc.Target {
	t.Helper()
	for _, tgt := range Targets {
		if tgt.Out == out {
			return tgt
		}
	}
	t.Fatalf("no target with Out %q", out)
	return configdoc.Target{}
}

// TestExecutorDoc checks the generated executor doc: comments resolved (including
// across package boundaries), values present, and the shared monitoring config
// rendered inline with its own fields' comments.
func TestExecutorDoc(t *testing.T) {
	out, err := newGenerator(t).Render(findTarget(t, "executor/config.documented.toml"))
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

	// monitoring is inlined, with its deprecation note and its own fields'
	// comments resolved from the common/monitoring package
	require.Contains(t, out, "# Monitoring is deprecated and ignored")
	require.Contains(t, out, "[Monitoring.Beholder]")
	require.Contains(t, out, "# LogLevel specifies the logging level")

	// top-level fields are separated by a blank line
	require.Contains(t, out, "indexer_address = [\"http://indexer-1:8080\", \"http://indexer-2:8080\"]\n\n#")
}

// TestExecutorDocDecodes proves the generated doc is a loadable config: it decodes
// through BurntSushi (strict) and passes the executor's real normalization, and
// the decoded config matches the documented instance (freshness oracle).
func TestExecutorDocDecodes(t *testing.T) {
	out, err := newGenerator(t).Render(findTarget(t, "executor/config.documented.toml"))
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
// the freshness + completeness guarantee. It runs in CI as a normal unit test.
func TestConfigDocsFresh(t *testing.T) {
	g := newGenerator(t)
	stale, err := g.Check(Targets, docsDir(g))
	require.NoError(t, err)
	for _, s := range stale {
		verb := "out of date"
		if s.Missing {
			verb = "missing"
		}
		t.Errorf("%s is %s; run: just config-docs", s.Target.Out, verb)
	}
}
