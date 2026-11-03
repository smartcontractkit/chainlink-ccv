package evmconfig

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/pelletier/go-toml/v2"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
)

// chainDefaultsFS holds the two layers of EVM chain defaults a Chainlink ccip node image resolves
// (chaindefaults/README.md). They are embedded and loaded here, leniently, instead of through
// CL_CHAIN_DEFAULTS: chainlink-evm exits at init on a file it cannot decode.
//
//go:embed chaindefaults/README.md chaindefaults/chainlink-evm/*.toml chaindefaults/ccip/*.toml
var chainDefaultsFS embed.FS

const (
	chainDefaultsReadme     = "chaindefaults/README.md"
	chainlinkEVMDefaultsDir = "chaindefaults/chainlink-evm"
	ccipDefaultsDir         = "chaindefaults/ccip"
)

// chainDefaultsLayer is one directory of chain defaults: a fallback and per-chain files. A file or
// key that does not load is named in problems and skipped; a layer never stops a process.
type chainDefaultsLayer struct {
	fallback *evmtoml.Chain
	chains   map[string]*evmtoml.Chain
	problems []string
}

type embeddedChainDefaults struct {
	chainlinkEVM, ccip             chainDefaultsLayer
	chainlinkEVMSource, ccipSource string
}

var loadedChainDefaults = sync.OnceValue(func() embeddedChainDefaults {
	return embeddedChainDefaults{
		chainlinkEVM:       loadChainDefaultsLayer(chainDefaultsFS, chainlinkEVMDefaultsDir),
		ccip:               loadChainDefaultsLayer(chainDefaultsFS, ccipDefaultsDir),
		chainlinkEVMSource: readmeSource(chainDefaultsFS, "chainlink-evm source: "),
		ccipSource:         readmeSource(chainDefaultsFS, "CCIP source: "),
	}
})

// chainDefaultsFile is one chain-defaults TOML file, the shape chainlink-evm reads.
type chainDefaultsFile struct {
	ChainID *sqlutil.Big
	evmtoml.Chain
}

func loadChainDefaultsLayer(fsys fs.FS, dir string) chainDefaultsLayer {
	layer := chainDefaultsLayer{chains: make(map[string]*evmtoml.Chain)}
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		layer.problems = append(layer.problems, fmt.Sprintf("skipped %s: %v", dir, err))
		return layer
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || path.Ext(name) != ".toml" {
			continue
		}
		data, err := fs.ReadFile(fsys, path.Join(dir, name))
		if err != nil {
			layer.problems = append(layer.problems, fmt.Sprintf("skipped %s: %v", name, err))
			continue
		}
		file, unknown, err := decodeChainDefaultsFile(data)
		if err != nil {
			layer.problems = append(layer.problems, fmt.Sprintf("skipped %s: %v", name, err))
			continue
		}
		if len(unknown) > 0 {
			layer.problems = append(layer.problems,
				fmt.Sprintf("ignored %s in %s, unknown to this release", strings.Join(unknown, ", "), name))
		}
		switch {
		case name == "fallback.toml":
			layer.fallback = &file.Chain
		case file.ChainID == nil:
			layer.problems = append(layer.problems, fmt.Sprintf("skipped %s: it has no ChainID", name))
		case layer.chains[file.ChainID.String()] != nil:
			layer.problems = append(layer.problems, fmt.Sprintf("skipped %s: chain %s already has a file", name, file.ChainID))
		default:
			layer.chains[file.ChainID.String()] = &file.Chain
		}
	}
	return layer
}

// decodeChainDefaultsFile decodes leniently: keys this release has no field for are returned, not
// fatal, and the rest of the file still applies.
func decodeChainDefaultsFile(data []byte) (chainDefaultsFile, []string, error) {
	var strictFile chainDefaultsFile
	err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&strictFile)
	if err == nil {
		return strictFile, nil, nil
	}
	var strict *toml.StrictMissingError
	if !errors.As(err, &strict) {
		return chainDefaultsFile{}, nil, err
	}
	var file chainDefaultsFile
	if err := toml.Unmarshal(data, &file); err != nil {
		return chainDefaultsFile{}, nil, err
	}
	unknown := make([]string, 0, len(strict.Errors))
	for _, decodeErr := range strict.Errors {
		unknown = append(unknown, strings.Join(decodeErr.Key(), "."))
	}
	sort.Strings(unknown)
	return file, unknown, nil
}

// readmeSource reads a provenance line the sync script maintains in the README.
func readmeSource(fsys fs.FS, prefix string) string {
	readme, err := fs.ReadFile(fsys, chainDefaultsReadme)
	if err != nil {
		return "unknown source"
	}
	for line := range strings.SplitSeq(string(readme), "\n") {
		if source, ok := strings.CutPrefix(line, prefix); ok {
			return strings.TrimSpace(source)
		}
	}
	return "unknown source"
}

// ChainDefaultsDir is the CL_CHAIN_DEFAULTS directory chainlink-evm applied at process start, or "".
// Leave it unset: the CCIP overrides are embedded, and chainlink-evm exits on a file it cannot decode.
func ChainDefaultsDir() string {
	return os.Getenv(evmtoml.ENV_CUSTOM_DEFAULTS)
}

// ChainDefaultsSource names the chain defaults standalone resolves against: the embedded layers, or
// chainlink-evm's own with the CL_CHAIN_DEFAULTS directory when the process was given one.
func ChainDefaultsSource() string {
	if dir := ChainDefaultsDir(); dir != "" {
		return "chainlink-evm built-ins with CL_CHAIN_DEFAULTS=" + dir
	}
	layers := loadedChainDefaults()
	return fmt.Sprintf("embedded: chainlink-evm built-ins from %s with CCIP overrides from %s",
		layers.chainlinkEVMSource, layers.ccipSource)
}

// ChainDefaultsProblems names the embedded default files or keys that did not load and were skipped.
// Empty in a release: TestChainDefaultsLoad keeps it that way.
func ChainDefaultsProblems() []string {
	if ChainDefaultsDir() != "" {
		return nil
	}
	layers := loadedChainDefaults()
	problems := make([]string, 0, len(layers.chainlinkEVM.problems)+len(layers.ccip.problems))
	for _, problem := range layers.chainlinkEVM.problems {
		problems = append(problems, "chainlink-evm defaults: "+problem)
	}
	for _, problem := range layers.ccip.problems {
		problems = append(problems, "CCIP defaults: "+problem)
	}
	return problems
}

// chainDefaults is the chain's defaults as a Chainlink ccip node image resolves them: CCIP's fallback,
// then chainlink-evm's file for the chain, then CCIP's file for it. A process started with
// CL_CHAIN_DEFAULTS already had chainlink-evm apply that directory, so its result is used as is.
func chainDefaults(chainID *sqlutil.Big) evmtoml.Chain {
	if ChainDefaultsDir() != "" {
		return evmtoml.Defaults(chainID)
	}
	layers := loadedChainDefaults()
	var chain evmtoml.Chain
	switch {
	case layers.ccip.fallback != nil:
		chain.SetFrom(layers.ccip.fallback)
	case layers.chainlinkEVM.fallback != nil:
		chain.SetFrom(layers.chainlinkEVM.fallback)
	default:
		chain = evmtoml.Defaults(nil)
	}
	if chainID == nil {
		return chain
	}
	if builtIn := layers.chainlinkEVM.chains[chainID.String()]; builtIn != nil {
		chain.SetFrom(builtIn)
	}
	if override := layers.ccip.chains[chainID.String()]; override != nil {
		chain.SetFrom(override)
	}
	return chain
}
