package config

import "time"

type IndexerConfig struct {
	Aggregator AggregatorConfig `toml:"Aggregator"`
	Scanner    ScannerConfig    `toml:"Scanner"`
	Storage    StorageConfig    `toml:"Storage"`
}

type AggregatorConfig struct {
	Enabled bool   `toml:"Enabled"`
	Address string `toml:"Address"`
}

type ScannerConfig struct {
	ScanInterval time.Duration `toml:"ScanInterval"`
}

type StorageConfig struct {
	Type string `toml:"Type"`
}
