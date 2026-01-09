package load

import (
	"time"

	"github.com/BurntSushi/toml"
)

// MessageProfileConfig corresponds to a message profile in the TOML config.
type MessageProfileConfig struct {
	Type     string `toml:"type"`     // "TT", "PTT", "Data"
	Finality int    `toml:"finality"` // e.g., 1
}

// ChainProfileConfig represents an entry in chain_profiles in the TOML config.
type ChainProfileConfig struct {
	RatioAsSource int `toml:"ratio_as_source"`
	RatioAsDest   int `toml:"ratio_as_dest"`
}

// MessageTestRatio ties a message ratio to a specific message_profile_index.
type MessageTestRatio struct {
	Ratio               int `toml:"ratio"`
	MessageProfileIndex int `toml:"message_profile_index"`
}

// TestProfileConfig represents each [test_profiles] block in the TOML config file.
type TestProfileConfig struct {
	ChainsAsSource    []string           `toml:"chains_as_source"`
	ChainsAsDest      []string           `toml:"chains_as_dest"`
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
