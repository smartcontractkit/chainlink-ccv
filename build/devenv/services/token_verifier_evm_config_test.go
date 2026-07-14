package services

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
)

func TestTokenVerifierAppConfigDoesNotContainEVMConnections(t *testing.T) {
	const selector = "5009297550715157269"
	in := TokenVerifierInput{GeneratedConfig: &token.Config{
		CommitteeConfig: chainaccess.CommitteeConfig{
			OnRampAddresses:    map[string]string{selector: "0x1111111111111111111111111111111111111111"},
			RMNRemoteAddresses: map[string]string{selector: "0x2222222222222222222222222222222222222222"},
		},
	}}

	appConfig, err := in.GenerateConfig()
	require.NoError(t, err)
	config := string(appConfig)
	require.NotContains(t, config, "blockchain_infos")
	require.Contains(t, config, "[on_ramp_addresses]")
	require.Contains(t, config, selector)
}

func TestDeprecatedTokenVerifierGeneratorKeepsConnectionFreeBlockchainInfos(t *testing.T) {
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

	appConfig, err := in.GenerateConfigWithBlockchainInfos(infos) //nolint:staticcheck // SA1019: exercises the deprecated compatibility wrapper
	require.NoError(t, err)
	require.Contains(t, string(appConfig), "blockchain_infos")
	require.NotContains(t, string(appConfig), "private-evm-node")
	require.Contains(t, string(appConfig), `chain_id = "1"`)
}
