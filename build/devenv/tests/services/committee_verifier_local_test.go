package services_test

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	_ "github.com/smartcontractkit/chainlink-ccv/build/devenv/evm" // registers the EVM chain config loader + verifier modifier
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
)

// TestServiceCommitteeVerifierLocalMode is an end-to-end check of bootstrap local mode
// (app_config_mode = "local_app_config"): it launches an EVM chain and an aggregator, then a committee
// verifier container whose app config is delivered via a mounted file instead of a Job Distributor.
// The verifier must boot (its Postgres keystore initialized locally), report the bootstrap health
// endpoint healthy, and serve its own /health — all without any JD in the environment.
//
// Named TestService... so the test-services CI job (which builds verifier:latest/aggregator:latest
// and runs -run TestService) picks it up. Requires Docker.
func TestServiceCommitteeVerifierLocalMode(t *testing.T) {
	const committeeName = "local"
	const verifierContainerName = "verifier-local"
	const chainID = "1337"

	// 1. Minimal EVM chain.
	chainOut, err := ctfblockchain.NewBlockchainNetwork(&ctfblockchain.Input{
		Type:          ctfblockchain.TypeAnvil,
		ChainID:       chainID,
		ContainerName: "anvil-local-1337",
	})
	require.NoError(t, err, "failed to launch anvil chain")

	details, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM)
	require.NoError(t, err)
	selectorStr := strconv.FormatUint(details.ChainSelector, 10)

	// 2. Aggregator with an HMAC credential the verifier will use (legacy default, un-suffixed).
	verifierCreds, err := hmacutil.GenerateCredentials()
	require.NoError(t, err)
	_, signerPublicKey, err := generateTestSigningKey(committeeName, 0)
	require.NoError(t, err)

	aggOut, err := services.NewAggregator(&services.AggregatorInput{
		CommitteeName: committeeName,
		Image:         "aggregator:latest",
		HostPort:      8203,
		DB: &services.AggregatorDBInput{
			Image:    "postgres:16-alpine",
			HostPort: 7532,
		},
		Redis: &services.AggregatorRedisInput{
			Image:    "redis:7-alpine",
			HostPort: 6479,
		},
		Env: &services.AggregatorEnvConfig{
			StorageConnectionURL: fmt.Sprintf("postgresql://%s:%s@%s-aggregator-db:5432/%s?sslmode=disable",
				services.DefaultAggregatorDBUsername,
				services.DefaultAggregatorDBPassword,
				committeeName,
				services.DefaultAggregatorDBName,
			),
			RedisAddress:  fmt.Sprintf("%s-aggregator-redis:6379", committeeName),
			RedisPassword: "",
			RedisDB:       "0",
		},
		APIClients: []*services.AggregatorClientConfig{{
			ClientID: verifierContainerName,
			Enabled:  true,
			Groups:   []string{},
			APIKeyPairs: []*services.AggregatorAPIKeyPair{{
				APIKey: verifierCreds.APIKey,
				Secret: verifierCreds.Secret,
			}},
		}},
		GeneratedCommittee: &model.Committee{
			QuorumConfigs: map[string]*model.QuorumConfig{
				selectorStr: {
					SourceVerifierAddress: "0x68B1D87F95878fE05B998F19b66F4baba5De1aed",
					Signers:               []model.Signer{{Address: signerPublicKey}},
					Threshold:             1,
				},
			},
			DestinationVerifiers: map[string]string{
				selectorStr: "0x68B1D87F95878fE05B998F19b66F4baba5De1aed",
			},
		},
	})
	require.NoError(t, err, "failed to launch aggregator")

	// 3. Minimal committee-verifier app config. Placeholder on-chain addresses are fine: the verifier
	//    does not validate them against the chain at startup. All three maps must share the same
	//    chain-selector key set (commit.Config.Validate).
	const placeholderAddr = "0x0000000000000000000000000000000000000001"
	appCfg := commit.Config{
		VerifierID: "local-verifier",
		Aggregators: []commit.AggregatorConnection{{
			Name:               "primary",
			Address:            aggOut.ExternalHTTPUrl, // internal <container>:50051 plaintext gRPC
			InsecureConnection: true,                   // avoids mounting the TLS CA cert
		}},
		CommitteeVerifierAddresses: map[string]string{selectorStr: placeholderAddr},
		CommitteeConfig: chainaccess.CommitteeConfig{
			OnRampAddresses:    map[string]string{selectorStr: placeholderAddr},
			RMNRemoteAddresses: map[string]string{selectorStr: placeholderAddr},
		},
	}
	require.NoError(t, appCfg.Validate(), "hand-built verifier config must be valid")

	// The app config contains only application-owned settings. The EVM modifier mounts RPC
	// connection details separately at the family-local config path.
	appCfgTOML, err := toml.Marshal(appCfg)
	require.NoError(t, err)

	// 4. Launch the verifier in local mode (no JD). New() blocks on the bootstrap /health wait, so a
	//    nil error already means local startup succeeded.
	in := committeeverifier.ApplyDefaults(committeeverifier.Input{
		Mode:          services.Local,
		ContainerName: verifierContainerName,
		CommitteeName: committeeName,
		ChainFamily:   chainsel.FamilyEVM,
		Env: &committeeverifier.EnvConfig{
			AggregatorAPIKey:    verifierCreds.APIKey,
			AggregatorSecretKey: verifierCreds.Secret,
		},
		LocalAppConfig: string(appCfgTOML),
	})

	out, err := committeeverifier.New(&in, []*ctfblockchain.Output{chainOut}, nil, chainreg.GetRegistry().GetVerifierModifiers())
	require.NoError(t, err, "verifier failed to launch in local mode")
	require.NotNil(t, out)

	// Keystore was initialized locally (no JD) — the ECDSA signing address is exposed via the
	// bootstrap info server.
	require.NotEmpty(t, out.BootstrapKeys.ECDSAAddress, "local mode must initialize the signing keystore")

	// 5. The verifier's own coordinator must come up healthy. Use a per-request timeout so a single
	//    stalled connection cannot block a poll longer than the Eventually interval.
	healthURL := out.ExternalHTTPURL + "/health"
	healthClient := &http.Client{Timeout: 3 * time.Second}
	require.Eventually(t, func() bool {
		resp, err := healthClient.Get(healthURL)
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == http.StatusOK
	}, 60*time.Second, 2*time.Second, "verifier /health did not become healthy in local mode")
}

// TestServiceCommitteeVerifierLocalModeDeferredConfig exercises the no-JD delivery path used by the
// full devenv local environment (app_config_source = "local"): the verifier is launched with NO app
// config, so its bootstrapper comes up serving keys and waiting; the config is delivered afterward via
// a file (DeliverLocalAppConfig), and only then does the verifier's coordinator start. This mirrors
// how JD delivers the app config after the verifier connects — the property the local path relies on
// so signer addresses can be read before contracts are configured and the config delivered after.
//
// Named TestService... so the test-services CI job picks it up. Requires Docker.
func TestServiceCommitteeVerifierLocalModeDeferredConfig(t *testing.T) {
	const committeeName = "localdefer"
	const verifierContainerName = "verifier-localdefer"
	const chainID = "1337"

	chainOut, err := ctfblockchain.NewBlockchainNetwork(&ctfblockchain.Input{
		Type:          ctfblockchain.TypeAnvil,
		ChainID:       chainID,
		ContainerName: "anvil-localdefer-1337",
		// Distinct host port from TestServiceCommitteeVerifierLocalMode's anvil (default 8545) so both
		// tests can run in the same session without a port clash.
		Port: "8547",
	})
	require.NoError(t, err, "failed to launch anvil chain")

	details, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM)
	require.NoError(t, err)
	selectorStr := strconv.FormatUint(details.ChainSelector, 10)

	verifierCreds, err := hmacutil.GenerateCredentials()
	require.NoError(t, err)
	_, signerPublicKey, err := generateTestSigningKey(committeeName, 0)
	require.NoError(t, err)

	aggOut, err := services.NewAggregator(&services.AggregatorInput{
		CommitteeName: committeeName,
		Image:         "aggregator:latest",
		HostPort:      8213,
		DB: &services.AggregatorDBInput{
			Image:    "postgres:16-alpine",
			HostPort: 7542,
		},
		Redis: &services.AggregatorRedisInput{
			Image:    "redis:7-alpine",
			HostPort: 6489,
		},
		Env: &services.AggregatorEnvConfig{
			StorageConnectionURL: fmt.Sprintf("postgresql://%s:%s@%s-aggregator-db:5432/%s?sslmode=disable",
				services.DefaultAggregatorDBUsername,
				services.DefaultAggregatorDBPassword,
				committeeName,
				services.DefaultAggregatorDBName,
			),
			RedisAddress:  fmt.Sprintf("%s-aggregator-redis:6379", committeeName),
			RedisPassword: "",
			RedisDB:       "0",
		},
		APIClients: []*services.AggregatorClientConfig{{
			ClientID: verifierContainerName,
			Enabled:  true,
			Groups:   []string{},
			APIKeyPairs: []*services.AggregatorAPIKeyPair{{
				APIKey: verifierCreds.APIKey,
				Secret: verifierCreds.Secret,
			}},
		}},
		GeneratedCommittee: &model.Committee{
			QuorumConfigs: map[string]*model.QuorumConfig{
				selectorStr: {
					SourceVerifierAddress: "0x68B1D87F95878fE05B998F19b66F4baba5De1aed",
					Signers:               []model.Signer{{Address: signerPublicKey}},
					Threshold:             1,
				},
			},
			DestinationVerifiers: map[string]string{
				selectorStr: "0x68B1D87F95878fE05B998F19b66F4baba5De1aed",
			},
		},
	})
	require.NoError(t, err, "failed to launch aggregator")

	// Launch the verifier in local mode WITHOUT an app config. New() blocks on the bootstrap /health
	// wait, so a nil error means the bootstrapper is up and serving keys while it waits for the config.
	in := committeeverifier.ApplyDefaults(committeeverifier.Input{
		Mode:          services.Local,
		ContainerName: verifierContainerName,
		CommitteeName: committeeName,
		ChainFamily:   chainsel.FamilyEVM,
		// Distinct DB name/port from TestServiceCommitteeVerifierLocalMode so both run in one session.
		DB: &committeeverifier.DBInput{
			Image: "postgres:16-alpine",
			Name:  "verifier-localdefer-db",
			Port:  8433,
		},
		Env: &committeeverifier.EnvConfig{
			AggregatorAPIKey:    verifierCreds.APIKey,
			AggregatorSecretKey: verifierCreds.Secret,
		},
		// LocalAppConfig intentionally left empty: delivered after launch, below.
	})

	out, err := committeeverifier.New(&in, []*ctfblockchain.Output{chainOut}, nil, chainreg.GetRegistry().GetVerifierModifiers())
	require.NoError(t, err, "verifier failed to launch in local mode (waiting for config)")
	require.NotNil(t, out)

	// Keys are exposed even before the config arrives — this is what lets the environment read the
	// signer address before contracts are configured.
	require.NotEmpty(t, out.BootstrapKeys.ECDSAAddress, "signing keystore must be initialized while waiting for config")
	require.NotNil(t, out.Container, "local mode must retain the container handle for app-config delivery")

	healthClient := &http.Client{Timeout: 3 * time.Second}
	verifierHealthy := func() bool {
		resp, err := healthClient.Get(out.ExternalHTTPURL + "/health")
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == http.StatusOK
	}

	// The coordinator (verifier :8100 /health) must NOT be up yet: no config has been delivered.
	require.False(t, verifierHealthy(), "verifier coordinator must not start before the config is delivered")

	// Build and deliver the app config; the waiting bootstrapper should then start the coordinator.
	const placeholderAddr = "0x0000000000000000000000000000000000000001"
	appCfg := commit.Config{
		VerifierID: "localdefer-verifier",
		Aggregators: []commit.AggregatorConnection{{
			Name:               "primary",
			Address:            aggOut.ExternalHTTPUrl,
			InsecureConnection: true,
		}},
		CommitteeVerifierAddresses: map[string]string{selectorStr: placeholderAddr},
		CommitteeConfig: chainaccess.CommitteeConfig{
			OnRampAddresses:    map[string]string{selectorStr: placeholderAddr},
			RMNRemoteAddresses: map[string]string{selectorStr: placeholderAddr},
		},
	}
	require.NoError(t, appCfg.Validate(), "hand-built verifier config must be valid")

	appCfgTOML, err := toml.Marshal(appCfg)
	require.NoError(t, err)

	require.NoError(t, committeeverifier.DeliverLocalAppConfig(out, string(appCfgTOML)),
		"failed to deliver app config to the waiting verifier")

	require.Eventually(t, verifierHealthy, 60*time.Second, 2*time.Second,
		"verifier coordinator did not become healthy after the config was delivered")
}
