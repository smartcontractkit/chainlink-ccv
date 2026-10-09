package services_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	chainsel "github.com/smartcontractkit/chain-selectors"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	_ "github.com/smartcontractkit/chainlink-ccv/build/devenv/evm" // registers the EVM chain config loader + verifier modifier
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/common/health"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
)

// degradedStack names one aggregator stack (aggregator, its DB and Redis, and the verifier) and
// fixes its host ports. Each test gets its own so containers and ports never collide.
type degradedStack struct {
	committee        string
	verifier         string
	dbName           string
	dbHostPort       int
	aggHostPort      int
	aggDBHostPort    int
	aggRedisHostPort int
}

// TestServiceCommitteeVerifierDegradedChain runs a verifier with one healthy and one unreachable EVM chain.
// The unreachable chain fails at startup, so the verifier must run and report /health as degraded.
// Named TestService... so the test-services CI job picks it up. Requires Docker.
func TestServiceCommitteeVerifierDegradedChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping service test in short mode; requires Docker service containers")
	}

	healthy, err := ctfblockchain.NewBlockchainNetwork(&ctfblockchain.Input{
		Type:          ctfblockchain.TypeAnvil,
		ChainID:       "1337",
		ContainerName: "anvil-degraded-1337",
	})
	require.NoError(t, err, "failed to launch anvil chain")
	terminateOnCleanup(t, healthy.Container)
	dead := unreachableEVMChain(t, "11155111")

	healthySel := evmSelectorString(t, "1337")
	deadSel := evmSelectorString(t, "11155111")
	stack := degradedStack{
		committee:        "degraded",
		verifier:         "degraded-verifier",
		dbName:           "degraded-db",
		dbHostPort:       8462,
		aggHostPort:      8263,
		aggDBHostPort:    7582,
		aggRedisHostPort: 6529,
	}

	out, err := launchDegradedCommitteeVerifier(t, stack, healthy, []*ctfblockchain.Output{healthy, dead}, []string{healthySel, deadSel})
	require.NoError(t, err, "a skipped chain must not stop the verifier from starting")
	require.NotNil(t, out)

	terminateOnCleanup(t, out.Container)
	// Registered after the terminate above, so this runs first and the log is still readable.
	var body health.ReadinessResponse
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("/health body: %+v", body)
			t.Logf("verifier log tail:\n%s", services.ContainerLogTail(context.Background(), out.Container, 64<<10))
		}
	})

	healthURL := out.ExternalHTTPURL + "/health"
	client := &http.Client{Timeout: 3 * time.Second}
	require.Eventually(t, func() bool {
		resp, err := client.Get(healthURL)
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		body = health.ReadinessResponse{}
		return resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&body) == nil
	}, 60*time.Second, 2*time.Second, "verifier /health did not answer 200 with a skipped chain")

	require.Equal(t, health.Degraded, body.Status, "one dead chain must degrade the verifier, not stop it")

	coordinator := findDegradedService(t, body, "verifier.Coordinator["+stack.verifier+"]")
	require.Equal(t, health.Ready, coordinator.Status, "the coordinator runs with the healthy chain")

	skips := findDegradedService(t, body, "verifier.StartupSkips")
	require.Equal(t, health.Degraded, skips.Status)
	require.Contains(t, skips.Error, fmt.Sprintf("Chain[%s]", deadSel), "the dead chain must be named")
	require.NotContains(t, skips.Error, fmt.Sprintf("Chain[%s]", healthySel), "the healthy chain must not be reported as skipped")
}

// TestServiceCommitteeVerifierNoUsableChain runs a verifier whose only chain is unreachable.
// With no usable chain the verifier must fail startup. Named TestService... (requires Docker).
func TestServiceCommitteeVerifierNoUsableChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping service test in short mode; requires Docker service containers")
	}

	dead := unreachableEVMChain(t, "11155111")
	deadSel := evmSelectorString(t, "11155111")
	stack := degradedStack{
		committee:        "unusable",
		verifier:         "unusable-verifier",
		dbName:           "unusable-db",
		dbHostPort:       8472,
		aggHostPort:      8273,
		aggDBHostPort:    7592,
		aggRedisHostPort: 6539,
	}

	_, err := launchDegradedCommitteeVerifier(t, stack, nil, []*ctfblockchain.Output{dead}, []string{deadSel})
	require.Error(t, err, "a verifier with no usable chain must not come up")
	require.ErrorContains(t, err, "verifier application did not become ready")
	require.ErrorContains(t, err, "no source readers configured", "the container log must show why startup failed")
}

// launchDegradedCommitteeVerifier starts an aggregator and a committee verifier in local mode. The
// app config lists every selector in selectors. stubChain is the healthy chain that hosts the stubbed
// OnRamp; pass nil when no chain is healthy. outputs are the EVM chains the verifier dials.
func launchDegradedCommitteeVerifier(
	t *testing.T,
	stack degradedStack,
	stubChain *ctfblockchain.Output,
	outputs []*ctfblockchain.Output,
	selectors []string,
) (*committeeverifier.Output, error) {
	t.Helper()

	verifierCreds, err := hmacutil.GenerateCredentials()
	require.NoError(t, err)
	privateKey, signerAddress, err := generateTestSigningKey(stack.committee, 0)
	require.NoError(t, err)
	bootstrapInput := testVerifierBootstrapWithImportedSigningKey(t, privateKey, signerAddress)

	const sourceVerifierAddr = "0x68B1D87F95878fE05B998F19b66F4baba5De1aed"
	quorumConfigs := make(map[string]*model.QuorumConfig, len(selectors))
	destVerifiers := make(map[string]string, len(selectors))
	for _, sel := range selectors {
		quorumConfigs[sel] = &model.QuorumConfig{
			SourceVerifierAddress: sourceVerifierAddr,
			Signers:               []model.Signer{{Address: signerAddress}},
			Threshold:             1,
		}
		destVerifiers[sel] = sourceVerifierAddr
	}

	aggOut, err := services.NewAggregator(&services.AggregatorInput{
		CommitteeName: stack.committee,
		Image:         "aggregator:latest",
		HostPort:      stack.aggHostPort,
		DB: &services.AggregatorDBInput{
			Image:    "postgres:16-alpine",
			HostPort: stack.aggDBHostPort,
		},
		Redis: &services.AggregatorRedisInput{
			Image:    "redis:7-alpine",
			HostPort: stack.aggRedisHostPort,
		},
		Env: &services.AggregatorEnvConfig{
			StorageConnectionURL: fmt.Sprintf("postgresql://%s:%s@%s-aggregator-db:5432/%s?sslmode=disable",
				services.DefaultAggregatorDBUsername,
				services.DefaultAggregatorDBPassword,
				stack.committee,
				services.DefaultAggregatorDBName,
			),
			RedisAddress:  fmt.Sprintf("%s-aggregator-redis:6379", stack.committee),
			RedisPassword: "",
			RedisDB:       "0",
		},
		APIClients: []*services.AggregatorClientConfig{{
			ClientID: stack.verifier,
			Enabled:  true,
			Groups:   []string{},
			APIKeyPairs: []*services.AggregatorAPIKeyPair{{
				APIKey: verifierCreds.APIKey,
				Secret: verifierCreds.Secret,
			}},
		}},
		GeneratedCommittee: &model.Committee{
			QuorumConfigs:        quorumConfigs,
			DestinationVerifiers: destVerifiers,
		},
	})
	require.NoError(t, err, "failed to launch aggregator")

	// Every selector goes into each map, because commit.Config.Validate requires the same key set.
	// The OnRamp stub only exists on the healthy chain; the dead chain never reaches that call.
	const placeholderAddr = "0x0000000000000000000000000000000000000001"
	if stubChain != nil {
		stubOnRampGetStaticConfig(t, stubChain.Nodes[0].ExternalHTTPUrl, placeholderOnRampAddr)
	}
	onRamps := make(map[string]string, len(selectors))
	committeeAddrs := make(map[string]string, len(selectors))
	rmnRemotes := make(map[string]string, len(selectors))
	for _, sel := range selectors {
		onRamps[sel] = placeholderOnRampAddr
		committeeAddrs[sel] = placeholderAddr
		rmnRemotes[sel] = placeholderAddr
	}
	appCfg := commit.Config{
		VerifierID:    stack.verifier,
		SignerAddress: signerAddress,
		Aggregators: []commit.AggregatorConnection{{
			Name:               "primary",
			Address:            aggOut.ExternalHTTPUrl,
			InsecureConnection: true,
		}},
		CommitteeVerifierAddresses: committeeAddrs,
		CommitteeConfig: chainaccess.CommitteeConfig{
			OnRampAddresses:    onRamps,
			RMNRemoteAddresses: rmnRemotes,
		},
	}
	require.NoError(t, appCfg.Validate(), "hand-built verifier config must be valid")
	appCfgTOML, err := toml.Marshal(appCfg)
	require.NoError(t, err)

	// The verifier DB defaults to one fixed container name and host port per chain family, so each
	// stack needs its own or a second verifier in the same run collides with the first.
	in := committeeverifier.ApplyDefaults(committeeverifier.Input{
		Mode:          services.Local,
		ContainerName: stack.verifier,
		CommitteeName: stack.committee,
		ChainFamily:   chainsel.FamilyEVM,
		DB: &committeeverifier.DBInput{
			Image: committeeverifier.DefaultVerifierDBImage,
			Name:  stack.dbName,
			Port:  stack.dbHostPort,
		},
		Bootstrap: bootstrapInput,
		Env: &committeeverifier.EnvConfig{
			AggregatorAPIKey:    verifierCreds.APIKey,
			AggregatorSecretKey: verifierCreds.Secret,
		},
		LocalAppConfig: string(appCfgTOML),
	})

	return committeeverifier.New(&in, outputs, nil, chainreg.GetRegistry().GetVerifierModifiers())
}

// unreachableEVMChain describes an EVM chain whose RPC hosts do not resolve, so dialing it fails at
// startup. The hostnames have no container behind them, so the failure is fast and certain.
func unreachableEVMChain(t *testing.T, chainID string) *ctfblockchain.Output {
	t.Helper()
	return &ctfblockchain.Output{
		Type:          ctfblockchain.TypeAnvil,
		Family:        chainsel.FamilyEVM,
		ChainID:       chainID,
		ContainerName: "unreachable-evm-" + chainID,
		Nodes: []*ctfblockchain.Node{{
			InternalHTTPUrl: "http://no-such-rpc-" + chainID + ":8545",
			InternalWSUrl:   "ws://no-such-rpc-" + chainID + ":8546",
			ExternalHTTPUrl: "http://127.0.0.1:1",
			ExternalWSUrl:   "ws://127.0.0.1:1",
		}},
	}
}

// evmSelectorString returns the chain selector for an EVM chain ID as the decimal string used as the
// key in the verifier's chain maps.
func evmSelectorString(t *testing.T, chainID string) string {
	t.Helper()
	details, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM)
	require.NoError(t, err)
	return strconv.FormatUint(details.ChainSelector, 10)
}

// findDegradedService returns the named service from a /health body, failing the test if it is absent.
func findDegradedService(t *testing.T, body health.ReadinessResponse, name string) health.ServicesHealth {
	t.Helper()
	for _, svc := range body.Services {
		if svc.Name == name {
			return svc
		}
	}
	require.Failf(t, "service missing from /health", "no service named %q in %+v", name, body.Services)
	return health.ServicesHealth{}
}

// terminateOnCleanup stops c when the test ends, so a failed run does not hold host ports that
// later tests in the package bind.
func terminateOnCleanup(t *testing.T, c testcontainers.Container) {
	t.Helper()
	if c == nil {
		return
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
}
