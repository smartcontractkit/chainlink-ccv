package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Profile encodes a complete, valid environment configuration.
type Profile struct {
	Environment string   `toml:"environment"`
	Configs     []string `toml:"configs"`
	Output      string   `toml:"output,omitempty"`
	Description string   `toml:"description,omitempty"`
}

// LoadProfile reads and validates a profile file.
func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading profile %s: %w", path, err)
	}
	var p Profile
	if err := toml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing profile %s: %w", path, err)
	}
	if p.Environment == "" {
		return nil, fmt.Errorf("profile %s: environment is required", path)
	}
	if len(p.Configs) == 0 {
		return nil, fmt.Errorf("profile %s: configs is required and must not be empty", path)
	}
	if p.Environment != "legacy" && p.Environment != "phased" {
		return nil, fmt.Errorf("profile %s: environment must be \"legacy\" or \"phased\", got %q", path, p.Environment)
	}
	return &p, nil
}

// OutputPath returns the output file path for the profile.
// If Output is explicitly set in the profile, that value is used; otherwise
// it is derived as "{base(configs[0])}-out.toml".
func (p *Profile) OutputPath() string {
	if p.Output != "" {
		return p.Output
	}
	return strings.TrimSuffix(p.Configs[0], ".toml") + "-out.toml"
}

// ProfileSuggest is a name/description pair for shell completion.
type ProfileSuggest struct {
	Name        string
	Description string
}

// ScanProfiles reads all *.profile files in dir and returns completion suggestions.
func ScanProfiles(dir string) []ProfileSuggest {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var results []ProfileSuggest
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".profile") {
			continue
		}
		desc := e.Name()
		p, err := LoadProfile(filepath.Join(dir, e.Name()))
		if err == nil && p.Description != "" {
			desc = p.Description
		}
		results = append(results, ProfileSuggest{Name: e.Name(), Description: desc})
	}
	return results
}
