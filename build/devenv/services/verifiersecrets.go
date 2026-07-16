package services

import (
	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
)

// GenerateVerifierSecrets marshals the verifier secrets file: the application storage DB
// URL and, for the committee verifier, per-aggregator HMAC credentials. It marshals
// vsecrets.SecretsFile directly so devenv and the runtime loader share one schema definition (the
// same single-source-of-truth dogfooding as GenerateBootstrapSecrets). Pass a nil aggregators slice
// for the token verifier, which uses only [db].
func GenerateVerifierSecrets(dbURL string, aggregators []vsecrets.AggregatorSecret) ([]byte, error) {
	return toml.Marshal(vsecrets.SecretsFile{
		DB:          vsecrets.DBSecrets{URL: dbURL},
		Aggregators: aggregators,
	})
}
