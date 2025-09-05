package verifier

type Configuration struct {
	AggregatorAddress string `toml:"aggregator_address"`
	CommitteeID       string `toml:"committee_id"`
}
