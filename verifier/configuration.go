package verifier

type Configuration struct {
	AggregatorAddress string `toml:"aggregator_address"`
	ParticipantID     string `toml:"participant_id"`
	CommitteeID       string `toml:"committee_id"`
}
