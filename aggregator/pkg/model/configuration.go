package model

type Signer struct {
	ParticipantID string `toml:"participantID"`
	Addresses     []byte `toml:"addresses"`
}

type Committee struct {
	// QuorumConfigs stores a QuorumConfig for each chain selector
	// there is a commit verifier for.
	// The aggregator uses this to verify signatures from each chain's
	// commit verifier set.
	QuorumConfigs map[uint64]QuorumConfig `toml:"quorumConfigs"`
}

type QuorumConfig struct {
	Signers []Signer `toml:"signers"`
	F       uint8    `toml:"f"`
}

type StorageConfig struct {
	StorageType string `toml:"type,default=memory"`
}

type AggregationConfig struct {
	AggregationStrategy string `toml:"strategy,default=stub"`
}

type AggregatorConfig struct {
	Storage     StorageConfig        `toml:"storage"`
	Aggregation AggregationConfig    `toml:"aggregation"`
	Committees  map[string]Committee `toml:"committees"`
}
