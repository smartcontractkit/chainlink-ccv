package services_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	gethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
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
	commonkeystore "github.com/smartcontractkit/chainlink-common/keystore"
)

const testVerifierKeyExportPassword = "export-password"

// testVerifierBootstrapWithImportedSigningKey builds the same OCR2 EVM key-export shape used by a
// Chainlink node and wires it into the standalone bootstrap config. The service tests can then use
// one deterministic identity for the aggregator signer set, signer_address, and verifier keystore.
func testVerifierBootstrapWithImportedSigningKey(
	t *testing.T,
	privateKeyHex string,
	signerAddress string,
) *services.BootstrapInput {
	t.Helper()

	privateKeyBytes, err := commit.ReadPrivateKeyFromString(privateKeyHex)
	require.NoError(t, err)
	privateKey, err := gethcrypto.ToECDSA(privateKeyBytes)
	require.NoError(t, err)

	bundle, err := json.Marshal(struct {
		ChainType       string `json:"ChainType"`
		OffchainKeyring []byte `json:"OffchainKeyring"`
		Keyring         []byte `json:"Keyring"`
		ID              []byte `json:"ID"`
	}{
		ChainType:       "evm",
		OffchainKeyring: make([]byte, 64),
		Keyring:         gethcrypto.FromECDSA(privateKey),
		ID:              make([]byte, 32),
	})
	require.NoError(t, err)

	cryptoJSON, err := gethkeystore.EncryptDataV3(
		bundle,
		[]byte("ocr2key"+testVerifierKeyExportPassword),
		commonkeystore.FastScryptParams.N,
		commonkeystore.FastScryptParams.P,
	)
	require.NoError(t, err)

	exportedKey, err := json.Marshal(struct {
		ChainType        string                  `json:"chainType"`
		OnchainPublicKey string                  `json:"onchainPublicKey"`
		Crypto           gethkeystore.CryptoJSON `json:"crypto"`
	}{
		ChainType:        "evm",
		OnchainPublicKey: hex.EncodeToString(gethcrypto.PubkeyToAddress(privateKey.PublicKey).Bytes()),
		Crypto:           cryptoJSON,
	})
	require.NoError(t, err)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ocr2.json")
	passwordPath := filepath.Join(dir, "password.txt")
	require.NoError(t, os.WriteFile(keyPath, exportedKey, 0o600))
	require.NoError(t, os.WriteFile(passwordPath, []byte(testVerifierKeyExportPassword), 0o600))

	keyImport, files, err := services.BuildKeyImport(keyPath, passwordPath, signerAddress)
	require.NoError(t, err)
	return &services.BootstrapInput{
		KeyImport:      keyImport,
		KeyImportFiles: files,
	}
}

// placeholderOnRampAddr is the OnRamp address these tests configure and stub. It deliberately sits
// outside the precompile range (0x01-0x11): calls to a precompile address are answered by the
// precompile itself, so stub bytecode installed there is ignored and getStaticConfig comes back
// empty.
const placeholderOnRampAddr = "0x0000000000000000000000000000000000001001"

// stubOnRampGetStaticConfig installs minimal bytecode at the placeholder OnRamp address so the
// source reader's construction-time RMN derivation succeeds: NewEVMSourceReader reads
// OnRamp.getStaticConfig() once at startup and fails if the read errors or returns a zero
// rmnRemote. These tests deploy no real contracts, so the placeholder must at least answer that
// one call. The stub returns an ABI-encoded OnRamp.StaticConfig (chainSelector, rmnRemote,
// nonceManager, tokenAdminRegistry — 4×32 bytes) whose only non-zero field is rmnRemote.
//
// The 14-byte runtime code returns its appended 128-byte payload for ANY call:
//
//	61 0080    PUSH2  128      ; payload length
//	60 0e      PUSH1  14       ; payload offset in code (right after this code)
//	60 00      PUSH1  0        ; memory destination
//	39         CODECOPY
//	61 0080    PUSH2  128
//	60 00      PUSH1  0
//	f3         RETURN
func stubOnRampGetStaticConfig(t *testing.T, rpcURL, onRampAddress string) {
	t.Helper()

	const rmnRemote = "00000000000000000000000000000000000000aa" // arbitrary, non-zero
	// The payload is the ABI-encoded getStaticConfig return tuple (4×32 bytes): chainSelector
	// (unused by the reader), rmnRemote (must be non-zero), maxUSDCentsPerMessage,
	// tokenAdminRegistry.
	payload := strings.Repeat("00", 32) +
		"000000000000000000000000" + rmnRemote +
		strings.Repeat("00", 32) +
		strings.Repeat("00", 32)
	code := "0x610080600e6000396100806000f3" + payload

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "anvil_setCode",
		"params":  []string{onRampAddress, code},
	})
	require.NoError(t, err)
	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(body))
	require.NoError(t, err, "anvil_setCode request failed")
	defer func() { _ = resp.Body.Close() }()
	var rpcResp struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&rpcResp))
	if rpcResp.Error != nil {
		t.Fatalf("anvil_setCode rejected the stub: %s", rpcResp.Error.Message)
	}
}

// TestServiceCommitteeVerifierLocalMode is an end-to-end check of bootstrap local mode
// (app_config_mode = "local_app_config"): it launches an EVM chain and an aggregator, then a committee
// verifier container whose app config is delivered via a mounted file instead of a Job Distributor.
// The verifier must boot (its Postgres keystore initialized locally), report the bootstrap health
// endpoint healthy, and serve its own /health — all without any JD in the environment.
//
// Named TestService... so the test-services CI job (which builds verifier:latest/aggregator:latest
// and runs -run TestService) picks it up. Requires Docker.
func TestServiceCommitteeVerifierLocalMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping service test in short mode; requires Docker service containers")
	}
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
	privateKey, signerAddress, err := generateTestSigningKey(committeeName, 0)
	require.NoError(t, err)
	bootstrapInput := testVerifierBootstrapWithImportedSigningKey(t, privateKey, signerAddress)

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
					Signers:               []model.Signer{{Address: signerAddress}},
					Threshold:             1,
				},
			},
			DestinationVerifiers: map[string]string{
				selectorStr: "0x68B1D87F95878fE05B998F19b66F4baba5De1aed",
			},
		},
	})
	require.NoError(t, err, "failed to launch aggregator")

	// 3. Minimal committee-verifier app config. Placeholder addresses are fine for everything except
	//    the OnRamp: the source reader reads its on-chain static config once at construction to derive
	//    the RMN Remote address, so the placeholder must answer getStaticConfig (stubbed below). The
	//    maps must share the same chain-selector key set (commit.Config.Validate).
	const placeholderAddr = "0x0000000000000000000000000000000000000001"
	stubOnRampGetStaticConfig(t, chainOut.Nodes[0].ExternalHTTPUrl, placeholderOnRampAddr)
	appCfg := commit.Config{
		VerifierID:    "local-verifier",
		SignerAddress: signerAddress,
		Aggregators: []commit.AggregatorConnection{{
			Name:               "primary",
			Address:            aggOut.ExternalHTTPUrl, // internal <container>:50051 plaintext gRPC
			InsecureConnection: true,                   // avoids mounting the TLS CA cert
		}},
		CommitteeVerifierAddresses: map[string]string{selectorStr: placeholderAddr},
		CommitteeConfig: chainaccess.CommitteeConfig{
			OnRampAddresses: map[string]string{selectorStr: placeholderOnRampAddr},
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
		Bootstrap:     bootstrapInput,
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
	require.Equal(t, signerAddress, "0x"+out.BootstrapKeys.ECDSAAddress,
		"local mode must import the signing identity declared in signer_address")

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
	if testing.Short() {
		t.Skip("skipping service test in short mode; requires Docker service containers")
	}
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
	privateKey, signerAddress, err := generateTestSigningKey(committeeName, 0)
	require.NoError(t, err)
	bootstrapInput := testVerifierBootstrapWithImportedSigningKey(t, privateKey, signerAddress)

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
					Signers:               []model.Signer{{Address: signerAddress}},
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
		Bootstrap:     bootstrapInput,
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
	require.Equal(t, signerAddress, "0x"+out.BootstrapKeys.ECDSAAddress,
		"signing identity must be imported while waiting for config")
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
	// The placeholder OnRamp must answer getStaticConfig (the reader derives the RMN Remote address
	// from it at construction), so stub it before delivery.
	const placeholderAddr = "0x0000000000000000000000000000000000000001"
	stubOnRampGetStaticConfig(t, chainOut.Nodes[0].ExternalHTTPUrl, placeholderOnRampAddr)
	appCfg := commit.Config{
		VerifierID:    "localdefer-verifier",
		SignerAddress: signerAddress,
		Aggregators: []commit.AggregatorConnection{{
			Name:               "primary",
			Address:            aggOut.ExternalHTTPUrl,
			InsecureConnection: true,
		}},
		CommitteeVerifierAddresses: map[string]string{selectorStr: placeholderAddr},
		CommitteeConfig: chainaccess.CommitteeConfig{
			OnRampAddresses: map[string]string{selectorStr: placeholderOnRampAddr},
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
