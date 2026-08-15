package services

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
)

func TestTokenVerifierAppConfigDoesNotContainEVMConnections(t *testing.T) {
	const selector = "5009297550715157269"
	in := TokenVerifierInput{GeneratedConfig: &token.Config{
		CommitteeConfig: chainaccess.CommitteeConfig{
			OnRampAddresses: map[string]string{selector: "0x1111111111111111111111111111111111111111"},
		},
	}}

	appConfig, err := in.GenerateConfig()
	require.NoError(t, err)
	config := string(appConfig)
	require.NotContains(t, config, "blockchain_infos")
	require.Contains(t, config, "[on_ramp_addresses]")
	require.Contains(t, config, selector)
}
