package load

import (
	"time"

	"github.com/BurntSushi/toml"
)

// MessageProfileConfig corresponds to a message profile in the TOML config.
type MessageProfileConfig struct {
	Type     string `toml:"type"`     // "TT", "PTT", "Data"
	Finality int    `toml:"finality"` // e.g., 1
	Name     string `toml:"name"`     // e.g., "data only"
}

// ChainProfileConfig represents an entry in chain_profiles in the TOML config.
type ChainProfileConfig struct {
	RatioAsSource int    `toml:"ratio_as_source"`
	RatioAsDest   int    `toml:"ratio_as_dest"`
	Name          string `toml:"name"` // e.g., "heavy"
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
	ChainsAsSource    []string           `toml:"chains_as_source"`
	ChainsAsDest      []string           `toml:"chains_as_dest"`
	Chains            []ChainTestConfig  `toml:"chains"`
	Messages          []MessageTestRatio `toml:"messages"`
	TestDuration      time.Duration      `toml:"test_duration"`
	LoadDuration      time.Duration      `toml:"load_duration"`
	MessagesPerSecond int64              `toml:"messages_per_second"`
}

// TOMLLoadTestRoot matches the structure of the TOML file for decoding.
type TOMLLoadTestRoot struct {
	ChainProfiles   []ChainProfileConfig   `toml:"chain_profiles"`
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
