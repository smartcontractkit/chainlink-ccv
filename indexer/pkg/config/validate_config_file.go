package config

import (
	"path/filepath"

	"github.com/smartcontractkit/chainlink-ccv/common/configvalidate"
)

// ValidateConfigFile strictly decodes the indexer config at configPath the same
// way LoadConfig does — the main document plus, when GeneratedConfigPath is set,
// the generated document resolved relative to it — and fails on decode errors and
// on keys that are absent from the config structs (drift, e.g. a renamed field
// that would otherwise be silently dropped and fall back to a default).
//
// When both documents decode cleanly it merges the generated config exactly as
// LoadConfig does and runs the secret-free validation (Config.ValidateWithoutSecrets),
// so a rendered config can be checked in CI with no secrets.toml present.
//
// It returns the generated-config verifier names that matched no entry in the main
// config. Those are not a failure: LoadConfig only logs them. Callers surface them
// as a warning.
func ValidateConfigFile(configPath string) (unmatched []string, err error) {
	var cfg Config
	mainUndecoded, mainErr := configvalidate.DecodeFileStrict(configPath, &cfg)
	results := []configvalidate.Result{{
		Name:      filepath.Base(configPath),
		Undecoded: mainUndecoded,
		Err:       mainErr,
	}}

	// Decode the generated config exactly as LoadConfig resolves it, but only when
	// the main config decoded far enough to give us a path.
	var generated *GeneratedConfig
	genErr := error(nil)
	if mainErr == nil && cfg.GeneratedConfigPath != "" {
		generatedPath := cfg.GeneratedConfigPath
		if !filepath.IsAbs(generatedPath) {
			generatedPath = filepath.Join(filepath.Dir(configPath), generatedPath)
		}

		var gen GeneratedConfig
		var genUndecoded []string
		genUndecoded, genErr = configvalidate.DecodeFileStrict(generatedPath, &gen)
		results = append(results, configvalidate.Result{
			Name:      filepath.Base(generatedPath),
			Undecoded: genUndecoded,
			Err:       genErr,
		})
		generated = &gen
	}

	// Once both documents decode cleanly, merge and run the service's own
	// secret-free validation. Skipped on any decode error, since the struct would be
	// incomplete.
	if mainErr == nil && genErr == nil {
		unmatched = MergeGeneratedConfig(&cfg, generated)
		if err := cfg.ValidateWithoutSecrets(); err != nil {
			results = append(results, configvalidate.Result{Name: "validation", Err: err})
		}
	}

	return unmatched, configvalidate.Report(results...)
}
