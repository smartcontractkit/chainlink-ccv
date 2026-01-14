package load

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// MessageProfileConfig corresponds to a message profile in the TOML config.
type MessageProfileConfig struct {
	Type     string `toml:"type"`     // "TT", "PTT", "Data"
	Finality int    `toml:"finality"` // e.g., 1
	Name     string `toml:"name"`     // e.g., "data only"
}

// ChainProfileConfig represents an chain in the test profile config.
type ChainProfileConfig struct {
	Ratio    int    `toml:"ratio"`
	Selector string `toml:"selector"` // e.g., "3379446385462418246"
}

// MessageTestRatio ties a message ratio to a specific message profile by name.
type MessageTestRatio struct {
	Ratio          int    `toml:"ratio"`
	MessageProfile string `toml:"message_profile"`
}

// ChainTestConfig represents a chain in the test with its associated profile.
type ChainTestConfig struct {
	Selector     string `toml:"selector"`
	ChainProfile string `toml:"chain_profile"`
}

// TestProfileConfig represents each [test_profiles] block in the TOML config file.
type TestProfileConfig struct {
	ChainsAsSource []ChainProfileConfig `toml:"chains_as_source"`
	ChainsAsDest   []ChainProfileConfig `toml:"chains_as_dest"`
	Chains         []ChainTestConfig    `toml:"chains"`
	Messages       []MessageTestRatio   `toml:"messages"`
	TestDuration   time.Duration        `toml:"test_duration"`
	LoadDuration   time.Duration        `toml:"load_duration"`
	MessageRate    string               `toml:"message_rate"`
}

// TOMLLoadTestRoot matches the structure of the TOML file for decoding.
type TOMLLoadTestRoot struct {
	MessageProfiles []MessageProfileConfig `toml:"message_profiles"`
	TestProfiles    []TestProfileConfig    `toml:"test_profiles"`
}

func LoadTestConfigFromTomlFile(tomlPath string) (*TOMLLoadTestRoot, error) {
	var cfg TOMLLoadTestRoot
	_, err := toml.DecodeFile(tomlPath, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

// GetSelectorByRatio selects a chain selector from the given slice based on ratio (weighted random selection)
// and returns it as uint64.
func GetSelectorByRatio(profiles []ChainProfileConfig) (uint64, error) {
	if len(profiles) == 0 {
		return 0, fmt.Errorf("no profiles provided")
	}

	// Calculate totalWeight weight
	totalWeight := 0
	for _, p := range profiles {
		totalWeight += p.Ratio
	}
	// Weighted random selection
	r := rand.IntN(totalWeight)
	accum := 0
	for _, p := range profiles {
		accum += p.Ratio
		if r < accum {
			selector, err := strconv.ParseUint(p.Selector, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("failed to parse selector %s: %w", p.Selector, err)
			}
			return selector, nil
		}
	}
	return 0, fmt.Errorf("no selector found after weighted random selection")
}

func GetMessageByRatio(profiles []MessageTestRatio, messageProfiles []MessageProfileConfig) (MessageProfileConfig, error) {
	if len(profiles) == 0 {
		return MessageProfileConfig{}, fmt.Errorf("no profiles provided")
	}

	totalWeight := 0
	for _, p := range profiles {
		totalWeight += p.Ratio
	}

	r := rand.IntN(totalWeight)
	accum := 0
	for _, p := range profiles {
		accum += p.Ratio
		if r < accum {
			for _, mp := range messageProfiles {
				if mp.Name == p.MessageProfile {
					return mp, nil
				}
			}
		}
	}
	return MessageProfileConfig{}, fmt.Errorf("no message profile found after weighted random selection")
}

func ParseMessageRate(messageRate string) (int64, time.Duration) {
	parts := strings.Split(messageRate, "/")
	if len(parts) != 2 {
		return 0, 0
	}
	rate, err := strconv.ParseInt(strings.Trim(parts[0], " "), 10, 64)
	if err != nil {
		return 0, 0
	}
	duration, err := time.ParseDuration(strings.Trim(parts[1], " "))
	if err != nil {
		return 0, 0
	}
	return rate, duration
}
