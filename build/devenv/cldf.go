package ccv

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	ccldf "github.com/smartcontractkit/chainlink-ccv/build/devenv/cldf"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	cldf_evm_provider "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider"
)

var Plog = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.DebugLevel).With().Fields(map[string]any{"component": "ccv"}).Logger()

// Type aliases so existing callers outside this package don't need to change imports.
type CLDF = ccldf.CLDF
type CLDFEnvironmentConfig = ccldf.CLDFEnvironmentConfig

func NewCLDFOperationsEnvironment(bc []*blockchain.Input, dataStore datastore.DataStore) ([]uint64, *deployment.Environment, error) {
	return ccldf.NewCLDFOperationsEnvironment(bc, dataStore)
}

func NewCLDFOperationsEnvironmentWithOffchain(cfg CLDFEnvironmentConfig) ([]uint64, *deployment.Environment, error) {
	return ccldf.NewCLDFOperationsEnvironmentWithOffchain(cfg)
}

func NewDefaultCLDFBundle(e *deployment.Environment) operations.Bundle {
	return ccldf.NewDefaultCLDFBundle(e)
}

func GenerateUserTransactors(privateKeys []string) []cldf_evm_provider.SignerGenerator {
	return ccldf.GenerateUserTransactors(privateKeys)
}
