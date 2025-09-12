package config

import "github.com/BurntSushi/toml"

func NewConfigFromPath(path string) (*IndexerConfig, error) {
	var config IndexerConfig

	// parse the toml config file
	_, err := toml.DecodeFile(path, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
