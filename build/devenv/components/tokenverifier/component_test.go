package tokenverifier

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/cctp"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/lombard"
)

func TestConfigForFamily(t *testing.T) {
	const local = "1"
	const remote = "2"

	generated := &token.Config{
		CommitteeConfig: chainaccess.CommitteeConfig{
			OnRampAddresses:    map[string]string{local: "local-onramp", remote: "remote-onramp"},
			RMNRemoteAddresses: map[string]string{local: "local-rmn", remote: "remote-rmn"},
		},
		TokenVerifiers: []token.VerifierConfig{
			{
				VerifierID: "cctp",
				CCTPConfig: &cctp.CCTPConfig{
					Verifiers:         map[string]any{local: "local-sender", remote: "remote-sender"},
					VerifierResolvers: map[string]any{local: "local-cctp-resolver", remote: "remote-cctp-resolver"},
				},
			},
			{
				VerifierID: "lombard",
				LombardConfig: &lombard.LombardConfig{
					VerifierResolvers: map[string]any{local: "local-lombard-resolver", remote: "remote-lombard-resolver"},
				},
			},
			{
				VerifierID: "remote-only",
				CCTPConfig: &cctp.CCTPConfig{
					Verifiers:         map[string]any{remote: "remote-sender"},
					VerifierResolvers: map[string]any{remote: "remote-cctp-resolver"},
				},
			},
		},
	}

	scoped := configForFamily(generated, []uint64{1})
	require.Equal(t, map[string]string{local: "local-onramp"}, scoped.OnRampAddresses)
	require.Equal(t, map[string]string{local: "local-rmn"}, scoped.RMNRemoteAddresses)
	require.Len(t, scoped.TokenVerifiers, 2)
	require.Equal(t, map[string]any{local: "local-sender"}, scoped.TokenVerifiers[0].CCTPConfig.Verifiers)
	require.Equal(t, generated.TokenVerifiers[0].CCTPConfig.VerifierResolvers, scoped.TokenVerifiers[0].CCTPConfig.VerifierResolvers)
	require.Equal(t, generated.TokenVerifiers[1].LombardConfig.VerifierResolvers, scoped.TokenVerifiers[1].LombardConfig.VerifierResolvers)

	scoped.OnRampAddresses[local] = "changed"
	scoped.RMNRemoteAddresses[local] = "changed"
	scoped.TokenVerifiers[0].CCTPConfig.Verifiers[local] = "changed"
	require.Equal(t, "local-onramp", generated.OnRampAddresses[local])
	require.Equal(t, "local-rmn", generated.RMNRemoteAddresses[local])
	require.Equal(t, "local-sender", generated.TokenVerifiers[0].CCTPConfig.Verifiers[local])
	require.Len(t, generated.TokenVerifiers, 3)
}
