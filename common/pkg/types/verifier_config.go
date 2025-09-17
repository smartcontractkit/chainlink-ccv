package types

type VerifierConfig struct {
	AggregatorAddress  string                     `toml:"aggregator_address"`
	PrivateKey         string                     `toml:"private_key"`
	BlockchainInfos    map[string]*BlockchainInfo `toml:"blockchain_infos"`
	VerifierOnRamp1337 string                     `toml:"verifier_on_ramp_1337"`
	VerifierOnRamp2337 string                     `toml:"verifier_on_ramp_2337"`
	CCVProxy1337       string                     `toml:"ccv_proxy_1337"`
	CCVProxy2337       string                     `toml:"ccv_proxy_2337"`
}
