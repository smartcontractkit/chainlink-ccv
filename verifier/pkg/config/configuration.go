package config

type Configuration struct {
	AggregatorAddress string `toml:"aggregator_address"`
	PrivateKey        string `toml:"private_key"`
}
