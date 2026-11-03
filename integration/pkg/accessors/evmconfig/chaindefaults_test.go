package evmconfig

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
)

// Both embedded layers load with this release's chainlink-evm types. A sync that brings in a key this
// release does not know shows up here; at runtime it would be skipped with a warning.
func TestChainDefaultsLoad(t *testing.T) {
	t.Parallel()

	for _, dir := range []string{chainlinkEVMDefaultsDir, ccipDefaultsDir} {
		layer := loadChainDefaultsLayer(chainDefaultsFS, dir)
		assert.Empty(t, layer.problems, dir)
		assert.NotNil(t, layer.fallback, dir)
		files, err := fs.Glob(chainDefaultsFS, dir+"/*.toml")
		require.NoError(t, err)
		assert.Len(t, layer.chains, len(files)-1, "%s: one file per chain, plus the fallback", dir)
	}
	layers := loadedChainDefaults()
	assert.True(t, strings.HasPrefix(layers.chainlinkEVMSource, "github.com/smartcontractkit/chainlink-evm@"), layers.chainlinkEVMSource)
	assert.True(t, strings.HasPrefix(layers.ccipSource, "smartcontractkit/chainlink@"), layers.ccipSource)
}

// The embedded chainlink-evm layer is the linked module's own defaults, so chainDefaults cannot drift
// from what chainlink-evm resolves.
func TestEmbeddedChainlinkEVMDefaultsMatchTheLinkedModule(t *testing.T) {
	if ChainDefaultsDir() != "" {
		t.Skip("CL_CHAIN_DEFAULTS is set for this process, so chainlink-evm's own defaults include it")
	}
	t.Parallel()

	const hint = "the embedded chainlink-evm defaults differ from the linked module; run `just sync-chain-defaults`"
	layer := loadChainDefaultsLayer(chainDefaultsFS, chainlinkEVMDefaultsDir)
	require.NotNil(t, layer.fallback, hint)
	assert.Empty(t, differingSettings(t, evmtoml.Defaults(nil), *layer.fallback), "%s: fallback", hint)

	linked := make(map[string]bool, len(evmtoml.DefaultIDs))
	for _, id := range evmtoml.DefaultIDs {
		linked[id.String()] = true
		embedded, ok := layer.chains[id.String()]
		if !assert.True(t, ok, "%s: chain %s has no file", hint, id) {
			continue
		}
		var chain evmtoml.Chain
		chain.SetFrom(layer.fallback)
		chain.SetFrom(embedded)
		assert.Empty(t, differingSettings(t, evmtoml.Defaults(id), chain), "%s: chain %s", hint, id)
	}
	for id := range layer.chains {
		assert.True(t, linked[id], "%s: chain %s is not in the linked module", hint, id)
	}
}

const chainDefaultsChildEnv = "CCV_TEST_CHAIN_DEFAULTS_OUT"

// chainDefaults must resolve every chain exactly as a Chainlink ccip node image does: chainlink-evm
// with CL_CHAIN_DEFAULTS on the same CCIP files. A child process computes that, because chainlink-evm
// reads the variable once, at init.
func TestChainDefaultsMatchACCIPNodeImage(t *testing.T) {
	ids := chainIDsWithDefaults()
	if out := os.Getenv(chainDefaultsChildEnv); out != "" {
		resolved := make(map[string]evmtoml.Chain, len(ids))
		for _, id := range ids {
			resolved[id] = evmtoml.Defaults(sqlutil.New(mustBigInt(t, id)))
		}
		data, err := json.Marshal(resolved)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(out, data, 0o600))
		return
	}
	if ChainDefaultsDir() != "" {
		t.Skip("CL_CHAIN_DEFAULTS is set for this process, so chainDefaults defers to chainlink-evm")
	}
	t.Parallel()

	// The ccip image's /ccip-config: CL_CHAIN_DEFAULTS names the directory that holds evm/.
	ccipConfig := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(ccipConfig, "evm"), 0o750))
	files, err := fs.Glob(chainDefaultsFS, ccipDefaultsDir+"/*.toml")
	require.NoError(t, err)
	for _, file := range files {
		data, err := fs.ReadFile(chainDefaultsFS, file)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(ccipConfig, "evm", path.Base(file)), data, 0o600))
	}

	out := filepath.Join(t.TempDir(), "node-image.json")
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestChainDefaultsMatchACCIPNodeImage$", "-test.count=1")
	cmd.Env = append(os.Environ(), evmtoml.ENV_CUSTOM_DEFAULTS+"="+ccipConfig, chainDefaultsChildEnv+"="+out)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "child with %s=%s failed:\n%s", evmtoml.ENV_CUSTOM_DEFAULTS, ccipConfig, output)

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	var nodeImage map[string]evmtoml.Chain
	require.NoError(t, json.Unmarshal(data, &nodeImage))
	require.Len(t, nodeImage, len(ids))
	for _, id := range ids {
		ours := chainDefaults(sqlutil.New(mustBigInt(t, id)))
		assert.Empty(t, differingSettings(t, nodeImage[id], ours), "chain %s: node image vs standalone", id)
	}
}

// A file or key that does not load is skipped and named; the rest of the layer still applies.
func TestLoadChainDefaultsLayerSkipsWhatItCannotRead(t *testing.T) {
	t.Parallel()

	fsys := fstest.MapFS{
		"defaults/fallback.toml":         {Data: []byte("FinalityDepth = 50\nFutureSetting = 1\n[GasEstimator]\nLimitMax = 8_000_000\n")},
		"defaults/Broken.toml":           {Data: []byte("ChainID = '1'\nFinalityDepth = \n")},
		"defaults/NoChainID.toml":        {Data: []byte("FinalityDepth = 3\n")},
		"defaults/Ethereum_Sepolia.toml": {Data: []byte("ChainID = '11155111'\nFinalityDepth = 7\n")},
		"defaults/Sepolia_Again.toml":    {Data: []byte("ChainID = '11155111'\nFinalityDepth = 9\n")},
	}
	layer := loadChainDefaultsLayer(fsys, "defaults")

	require.NotNil(t, layer.fallback)
	assert.Equal(t, uint32(50), *layer.fallback.FinalityDepth, "an unknown key costs that key, not the file")
	assert.Equal(t, uint64(8_000_000), *layer.fallback.GasEstimator.LimitMax)
	require.Contains(t, layer.chains, "11155111")
	assert.Equal(t, uint32(7), *layer.chains["11155111"].FinalityDepth, "the first file for a chain wins")
	require.Len(t, layer.problems, 4)
	assert.Contains(t, layer.problems[0], "skipped Broken.toml")
	assert.Equal(t, "skipped NoChainID.toml: it has no ChainID", layer.problems[1])
	assert.Equal(t, "skipped Sepolia_Again.toml: chain 11155111 already has a file", layer.problems[2])
	assert.Equal(t, "ignored FutureSetting in fallback.toml, unknown to this release", layer.problems[3])

	missing := loadChainDefaultsLayer(fsys, "nowhere")
	assert.Nil(t, missing.fallback)
	require.Len(t, missing.problems, 1, "a missing layer is a problem, not a failure")
}

func chainIDsWithDefaults() []string {
	seen := map[string]bool{"424242424242": true} // no file in either layer: the fallback alone
	for _, id := range evmtoml.DefaultIDs {
		seen[id.String()] = true
	}
	for id := range loadChainDefaultsLayer(chainDefaultsFS, ccipDefaultsDir).chains {
		seen[id] = true
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func mustBigInt(t *testing.T, id string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(id, 10)
	require.True(t, ok, id)
	return n
}

// differingSettings lists, as "path: want != got", the settings two chain configs disagree on.
func differingSettings(t *testing.T, want, got evmtoml.Chain) []string {
	t.Helper()
	flat := func(chain evmtoml.Chain) map[string]any {
		data, err := json.Marshal(chain)
		require.NoError(t, err)
		var tree map[string]any
		require.NoError(t, json.Unmarshal(data, &tree))
		out := map[string]any{}
		var walk func(prefix string, node map[string]any)
		walk = func(prefix string, node map[string]any) {
			for key, value := range node {
				if nested, ok := value.(map[string]any); ok {
					walk(joinSettingPath(prefix, key), nested)
					continue
				}
				out[joinSettingPath(prefix, key)] = value
			}
		}
		walk("", tree)
		return out
	}
	wantFlat, gotFlat := flat(want), flat(got)
	var diffs []string
	for key := range wantFlat {
		if !reflect.DeepEqual(wantFlat[key], gotFlat[key]) {
			diffs = append(diffs, fmt.Sprintf("%s: %v != %v", key, wantFlat[key], gotFlat[key]))
		}
	}
	for key := range gotFlat {
		if _, ok := wantFlat[key]; !ok {
			diffs = append(diffs, fmt.Sprintf("%s: <unset> != %v", key, gotFlat[key]))
		}
	}
	sort.Strings(diffs)
	return diffs
}
