package devutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	// DefaultConfigDir is the default directory we are expecting TOML config to be.
	DefaultConfigDir = "."
	// EnvVarTestConfigs is the environment variable name to read config paths from, ex.: CTF_CONFIGS=env.toml,overrides.toml.
	EnvVarTestConfigs = "CTF_CONFIGS"
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
