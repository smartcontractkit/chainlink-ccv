package services

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
)

func TestTokenVerifierAppConfigDoesNotContainEVMConnections(t *testing.T) {
	in := TokenVerifierInput{GeneratedConfig: &token.Config{}}
	infos := chainaccess.Infos[evm.Info]{
		"5009297550715157269": {
			ChainID: "1",
			Family:  "evm",
			Nodes: []evm.Node{{
				InternalHTTPUrl: "http://private-evm-node:8545",
				InternalWSUrl:   "ws://private-evm-node:8546",
			}},
		},
	}

	appConfig, err := in.GenerateConfigWithBlockchainInfos(infos)
	require.NoError(t, err)
	require.NotContains(t, string(appConfig), "private-evm-node")
	require.Contains(t, string(appConfig), `chain_id = "1"`)
}
