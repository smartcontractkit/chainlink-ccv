package ccv

/*
This file provides a simple boilerplate for TOML configuration with overrides
It has 3 functions: Load[T], Store[T] and LoadCache[T]

To configure the environment we use a set of files we read from the env var CTF_CONFIGS=env.toml,overrides.toml (can be more than 2) in Load[T]
To store infra or product component outputs we use Store[T] that creates env-cache.toml file.
This file can be used in tests or in any other code that integrated with dev environment.
LoadCache[T] is used if you need to write outputs the second time.
*/

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
)

const (
	// DefaultConfigDir is the default directory we are expecting TOML config to be.
	DefaultConfigDir = "."
	// EnvVarTestConfigs is the environment variable name to read config paths from, ex.: CTF_CONFIGS=env.toml,overrides.toml.
	EnvVarTestConfigs = "CTF_CONFIGS"
	// EnvVarTestOutput overrides the output file path written by Store. When unset
	// the path is derived from the first entry in CTF_CONFIGS.
	EnvVarTestOutput = "CTF_OUTPUT"
	DefaultLokiURL   = "http://localhost:3030/loki/api/v1/push"
	DefaultTempoURL  = "http://localhost:4318/v1/traces"
)

var L = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.InfoLevel)

// Load loads TOML configurations from a list of paths, i.e. env.toml,overrides.toml
// and unmarshalls the files from left to right overriding keys.
func Load[T any](paths []string) (*T, error) {
	var config T
	for _, path := range paths {
		L.Info().Str("Path", path).Msg("Loading configuration input")
		data, err := os.ReadFile(filepath.Join(DefaultConfigDir, path))
		if err != nil {
			return nil, fmt.Errorf("error reading config file %s: %w", path, err)
		}
		if L.GetLevel() == zerolog.TraceLevel {
			fmt.Println(string(data))
		}

		decoder := toml.NewDecoder(strings.NewReader(string(data)))
		decoder.DisallowUnknownFields()

		if err := decoder.Decode(&config); err != nil {
			var details *toml.StrictMissingError
			if errors.As(err, &details) {
				fmt.Println(details.String())
			}
			return nil, fmt.Errorf("failed to decode TOML config, strict mode: %s", err)
		}
	}
	if L.GetLevel() == zerolog.TraceLevel {
		L.Trace().Msg("Merged inputs")
		spew.Dump(config)
	}
	return &config, nil
}

// Store writes config to a file, adds -out.toml suffix if it's an initial configuration.
// The output path may be overridden via the CTF_OUTPUT environment variable.
func Store[T any](cfg *T) error {
	var outCacheName string
	if override := os.Getenv(EnvVarTestOutput); override != "" {
		outCacheName = override
	} else {
		baseConfigPath, err := BaseConfigPath()
		if err != nil {
			return err
		}
		newCacheName := strings.ReplaceAll(baseConfigPath, ".toml", "")
		if strings.Contains(newCacheName, "cache") {
			L.Info().Str("Cache", baseConfigPath).Msg("Cache file already exists, overriding")
			outCacheName = baseConfigPath
		} else {
			outCacheName = fmt.Sprintf("%s-out.toml", strings.ReplaceAll(baseConfigPath, ".toml", ""))
		}
	}
	L.Info().Str("OutputFile", outCacheName).Msg("Storing configuration output")
	d, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(DefaultConfigDir, outCacheName), d, 0o600)
}

// LoadOutput loads a devenv output file and returns a populated *Cfg. It
// supports two output formats, distinguished by the top-level "version" key:
//
//   - version 0 / absent — the legacy monolith output, a strict Cfg dump.
//   - version 1 — the phased output, a raw component-output map; the required
//     components are decoded out of it and the endpoint maps are derived.
//
// Either way it rebuilds the CLDF datastore from the deployed addresses. The
// generic T is retained for the existing call sites; only *Cfg is supported.
func LoadOutput[T any](outputPath string) (*T, error) {
	data, err := os.ReadFile(filepath.Join(DefaultConfigDir, outputPath))
	if err != nil {
		return nil, fmt.Errorf("error reading config file %s: %w", outputPath, err)
	}

	// Peek the schema version to choose the decoder.
	var probe struct {
		Version int `toml:"version"`
	}
	if err := toml.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("failed to read config version from %s: %w", outputPath, err)
	}

	var c *Cfg
	switch probe.Version {
	case 0:
		c, err = loadLegacyCfg(data)
	case 1:
		c, err = loadPhasedCfg(data)
	default:
		return nil, fmt.Errorf("unsupported output version %d; supported version is 1", probe.Version)
	}
	if err != nil {
		return nil, err
	}

	if len(c.CLDF.Addresses) <= 0 {
		return nil, fmt.Errorf("no addresses found in config")
	}

	// Load addresses into the datastore so that tests can query them appropriately.
	ds := datastore.NewMemoryDataStore()
	for _, addrRefJSON := range c.CLDF.Addresses {
		var addrs []datastore.AddressRef
		if err := json.Unmarshal([]byte(addrRefJSON), &addrs); err != nil {
			return nil, fmt.Errorf("failed to unmarshal addresses from config: %w", err)
		}
		for _, addr := range addrs {
			if err := ds.Addresses().Add(addr); err != nil {
				return nil, fmt.Errorf("failed to set address in datastore: %w", err)
			}
		}
	}

	// Load env metadata into the datastore so that tests can query it appropriately.
	var dsMetaData datastore.EnvMetadata
	if c.CLDF.EnvMetadata != "" {
		if err := json.Unmarshal([]byte(c.CLDF.EnvMetadata), &dsMetaData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal env metadata from config: %w", err)
		}
	}
	if err := ds.EnvMetadata().Set(dsMetaData); err != nil {
		return nil, fmt.Errorf("failed to set env metadata in datastore: %w", err)
	}

	c.CLDF.DataStore = ds.Seal()

	out, ok := any(c).(*T)
	if !ok {
		return nil, fmt.Errorf("config is not a *Cfg")
	}
	return out, nil
}

// loadLegacyCfg strict-decodes the monolith output into a Cfg, rejecting
// unknown keys (matching Load's behavior).
func loadLegacyCfg(data []byte) (*Cfg, error) {
	var cfg Cfg
	decoder := toml.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		var details *toml.StrictMissingError
		if errors.As(err, &details) {
			fmt.Println(details.String())
		}
		return nil, fmt.Errorf("failed to decode TOML config, strict mode: %s", err)
	}
	return &cfg, nil
}

// loadPhasedCfg builds a Cfg from a phased (version 1) output file. The file is
// a raw component-output dump, so it is decoded leniently (it carries keys Cfg
// does not model, e.g. the aggregators/verifiers plurals owned by the
// committeeccv component). Those plurals are decoded explicitly and the
// aggregator/indexer endpoint maps are derived from each launched service's Out.
func loadPhasedCfg(data []byte) (*Cfg, error) {
	var cfg Cfg
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to decode phased output: %w", err)
	}

	var extra struct {
		Aggregators []*services.AggregatorInput `toml:"aggregators"`
		Verifiers   []*committeeverifier.Input  `toml:"verifiers"`
	}
	if err := toml.Unmarshal(data, &extra); err != nil {
		return nil, fmt.Errorf("failed to decode phased aggregators/verifiers: %w", err)
	}
	cfg.Aggregator = extra.Aggregators
	cfg.Verifier = extra.Verifiers

	cfg.AggregatorEndpoints = make(map[string]string)
	cfg.AggregatorCACertFiles = make(map[string]string)
	for _, agg := range cfg.Aggregator {
		if agg.Out == nil {
			continue
		}
		cfg.AggregatorEndpoints[agg.CommitteeName] = agg.Out.ExternalHTTPSUrl
		if agg.Out.TLSCACertFile != "" {
			cfg.AggregatorCACertFiles[agg.CommitteeName] = agg.Out.TLSCACertFile
		}
	}

	externalURLs := make([]string, 0, len(cfg.Indexer))
	internalURLs := make([]string, 0, len(cfg.Indexer))
	for _, idxIn := range cfg.Indexer {
		if idxIn.Out == nil {
			continue
		}
		externalURLs = append(externalURLs, idxIn.Out.ExternalHTTPURL)
		internalURLs = append(internalURLs, idxIn.Out.InternalHTTPURL)
	}
	cfg.IndexerEndpoints = externalURLs
	cfg.IndexerInternalEndpoints = internalURLs

	return &cfg, nil
}

// BaseConfigPath returns base config path, ex. env.toml,overrides.toml -> env.toml.
func BaseConfigPath() (string, error) {
	configs := os.Getenv(EnvVarTestConfigs)
	if configs == "" {
		return "", fmt.Errorf("no %s env var is provided, you should provide at least one test config in TOML", EnvVarTestConfigs)
	}
	L.Debug().Str("Configs", configs).Msg("Getting base config path")
	return strings.Split(configs, ",")[0], nil
}

// loadRaw loads TOML configuration files into an opaque map, merging multiple
// files left-to-right. This is used by the component runtime to route top-level
// config keys to registered components. Validation is not performed here; each
// component is responsible for validating its own config slice.
func loadRaw(paths []string) (map[string]any, error) {
	result := map[string]any{}
	for _, path := range paths {
		L.Info().Str("Path", path).Msg("Loading configuration input")
		data, err := os.ReadFile(filepath.Join(DefaultConfigDir, path))
		if err != nil {
			return nil, fmt.Errorf("error reading config file %s: %w", path, err)
		}
		// Unmarshal into a fresh map to avoid go-toml panicking when SetLen is
		// called on an array-table slice stored as interface{} in a reused map.
		var fileMap map[string]any
		if err := toml.Unmarshal(data, &fileMap); err != nil {
			return nil, fmt.Errorf("failed to decode config %s: %w", path, err)
		}
		deepMergeMaps(result, fileMap)
	}
	return result, nil
}

// deepMergeMaps merges src into dst recursively. Nested maps are merged
// key-by-key; all other values (scalars, slices) are replaced wholesale.
// This preserves keys in dst that are absent from src, which is required
// for overlay configs that only specify a sub-section of a nested table
// (e.g. environment_topology.executor_pools without touching nop_topology).
func deepMergeMaps(dst, src map[string]any) {
	for k, srcVal := range src {
		if dstVal, ok := dst[k]; ok {
			if dstMap, ok := dstVal.(map[string]any); ok {
				if srcMap, ok := srcVal.(map[string]any); ok {
					deepMergeMaps(dstMap, srcMap)
					continue
				}
			}
		}
		dst[k] = srcVal
	}
}

func getNetworkPrivateKey() string {
	pk := os.Getenv("PRIVATE_KEY")
	if pk == "" {
		// that's the first Anvil and Geth private key, serves as a fallback for local testing if not overridden
		return devenvcommon.DefaultAnvilKey
	}
	return pk
}

func GetUserPrivateKeys() []string {
	userPrivateKeys, idx := []string{getNetworkPrivateKey()}, 0
	for {
		idx++
		pk := os.Getenv(fmt.Sprintf("PRIVATE_KEY_%d", idx))
		if pk == "" {
			break
		}
		userPrivateKeys = append(userPrivateKeys, pk)
	}
	return userPrivateKeys
}
