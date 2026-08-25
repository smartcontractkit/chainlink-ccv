package services_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/health"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/cctp"
)

// TestServiceTokenVerifierWithoutDeprecatedRMNRemoteAddresses boots a token verifier against an app
// config that sets on_ramp_addresses and no rmn_remote_addresses, which is the shape a config
// generated after the RMN-derivation cutover has: the RMN Remote address comes from the OnRamp's
// on-chain static config, so the deprecated per-chain map is absent.
//
// This is the config that took down the prod-testnet and prod-mainnet token verifiers
// (chainlink-ccv-deploy#374). The accessor factory used to require both an on-ramp and an RMN
// Remote address before it would build a source reader, so every chain failed with "cannot get
// accessor for chain <selector>: neither source nor destination services are configured". The token
// verifier logs that per chain and carries on, so the visible symptom was the coordinator dying at
// startup with "no enabled/initialized chain sources, nothing to coordinate" — a crash loop that
// only stopped once the deprecated addresses were pasted back into the config.
//
// The assertion that matters is that the service starts at all: services.NewTokenVerifier waits for
// the "Verifier service fully started and ready" log line, which the coordinator only reaches with a
// live source reader for the configured chain.
//
// Named TestService... so the test-services CI job (which builds token-verifier:latest and runs
// -run TestService) picks it up. Requires Docker.
func TestServiceTokenVerifierWithoutDeprecatedRMNRemoteAddresses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping service test in short mode; requires Docker service containers")
	}
	const chainID = "1337"
	const containerName = "token-verifier-derived-rmn"

	// Distinct container name and host port from the other service tests' anvils so the whole
	// suite can run in one session.
	chainOut, err := ctfblockchain.NewBlockchainNetwork(&ctfblockchain.Input{
		Type:          ctfblockchain.TypeAnvil,
		ChainID:       chainID,
		ContainerName: "anvil-tokenverifier-1337",
		Port:          "8549",
	})
	require.NoError(t, err, "failed to launch anvil chain")

	details, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM)
	require.NoError(t, err)
	selectorStr := strconv.FormatUint(details.ChainSelector, 10)

	// With no configured RMN Remote there is nothing to fall back on, so the derivation is the only
	// path: stub the placeholder OnRamp so getStaticConfig answers with a non-zero rmnRemote.
	stubOnRampGetStaticConfig(t, chainOut.Nodes[0].ExternalHTTPUrl, placeholderOnRampAddr)

	const placeholderAddr = "0x0000000000000000000000000000000000000001"
	in := services.ApplyTokenVerifierDefaults(services.TokenVerifierInput{
		ContainerName: containerName,
		Port:          8701,
		DB: &services.TokenVerifierDBInput{
			Image: "postgres:16-alpine",
			Name:  containerName + "-db",
			Port:  8451,
		},
		GeneratedConfig: &token.Config{
			CommitteeConfig: chainaccess.CommitteeConfig{
				OnRampAddresses: map[string]string{selectorStr: placeholderOnRampAddr},
				// RMNRemoteAddresses deliberately unset: a nil map marshals to no
				// [rmn_remote_addresses] table at all, matching the deployed config.
			},
			TokenVerifiers: []token.VerifierConfig{{
				VerifierID: "cctp-local",
				Type:       "cctp",
				Version:    "2.0",
				CCTPConfig: &cctp.CCTPConfig{
					// Unreachable on purpose. Attestation fetching is background work, so it must
					// not hold up startup; a reachable API would only add a network dependency.
					AttestationAPI:                "http://127.0.0.1:1/attestation",
					AttestationAPITimeout:         time.Second,
					AttestationAPIInterval:        100 * time.Millisecond,
					AttestationAPICooldown:        5 * time.Minute,
					AttestationConcurrentFetchers: 1,
					// The resolver map is what becomes the coordinator's source configs, so the
					// chain must appear here for its source reader to count as enabled.
					Verifiers:         map[string]any{selectorStr: placeholderAddr},
					VerifierResolvers: map[string]any{selectorStr: placeholderAddr},
				},
			}},
		},
	})

	out, err := services.NewTokenVerifier(&in, []*ctfblockchain.Output{chainOut})
	require.NoError(t, err, "token verifier failed to start with a config that omits rmn_remote_addresses")
	require.NotNil(t, out)

	// Readiness reports one entry per coordinator. An entry that is ready means the coordinator
	// found a source reader for the configured chain rather than being skipped.
	healthClient := &http.Client{Timeout: 3 * time.Second}
	var readiness health.ReadinessResponse
	require.Eventually(t, func() bool {
		resp, err := healthClient.Get(out.ExternalHTTPURL + "/health/ready")
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return false
		}
		readiness = health.ReadinessResponse{}
		return json.NewDecoder(resp.Body).Decode(&readiness) == nil
	}, 60*time.Second, 2*time.Second, "token verifier /health/ready did not report ready")

	require.Equal(t, health.Ready, readiness.Status)
	require.Len(t, readiness.Services, 1, "the configured CCTP coordinator must be reported")
	require.Equal(t, health.Ready, readiness.Services[0].Status, "coordinator %q is not ready: %s",
		readiness.Services[0].Name, readiness.Services[0].Error)
}
