package constructors

import (
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
)

// CCVConfig holds the configuration needed to configure the CCV services.
type CCVConfig struct {
	Verifiers []commit.Config
	Executor  executor.Configuration
}

type VerifierSecrets struct {
	SigningKey string
}

type CCVSecretsConfig struct {
	Verifier VerifierSecrets
}
