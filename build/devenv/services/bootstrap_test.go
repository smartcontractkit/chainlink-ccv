package services

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/common/monitoring"
)

// validEd25519PublicKeyHex is 32 bytes (64 hex chars), accepted by JDConfig validation.
const validEd25519PublicKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestGenerateBootstrap_SplitFiles locks in the config/secrets split: the non-secret file
// carries only [jd]/[server]/[[chains]]/[Monitoring] and the secrets file carries only
// [keystore]/[db]; decoding both into one bootstrap.Config reconstructs the full, valid config.
func TestGenerateBootstrap_SplitFiles(t *testing.T) {
	in := BootstrapInput{
		Keystore: &bootstrap.KeystoreConfig{Password: "s3cret"},
		Server:   &bootstrap.ServerConfig{ListenPort: 9988},
		DB:       &bootstrap.DBConfig{URL: "postgres://user:pass@host:5432/db"},
		JD: &bootstrap.JDConfig{
			ServerWSRPCURL:     "ws://jd:8080/ws",
			ServerCSAPublicKey: validEd25519PublicKeyHex,
		},
		Chains: []bootstrap.ChainRegistration{{Type: "EVM", ID: "1"}},
	}

	configTOML, err := GenerateBootstrapConfig(in)
	require.NoError(t, err)
	secretsTOML, err := GenerateBootstrapSecrets(in)
	require.NoError(t, err)

	// The non-secret file must not carry credentials.
	require.NotContains(t, string(configTOML), "s3cret")
	require.NotContains(t, string(configTOML), "postgres://")
	// The secrets file must not carry the non-secret sections.
	require.NotContains(t, string(secretsTOML), "server_wsrpc_url")
	require.NotContains(t, string(secretsTOML), "listen_port")

	// Decoding both into one struct (config first, secrets overlay) reconstructs the full config.
	var cfg bootstrap.Config
	_, err = toml.Decode(string(configTOML), &cfg)
	require.NoError(t, err)
	_, err = toml.Decode(string(secretsTOML), &cfg)
	require.NoError(t, err)

	require.Equal(t, "ws://jd:8080/ws", cfg.JD.ServerWSRPCURL)
	require.Equal(t, 9988, cfg.Server.ListenPort)
	require.Len(t, cfg.Chains, 1)
	require.Equal(t, "s3cret", cfg.Keystore.Password)
	require.Equal(t, "postgres://user:pass@host:5432/db", cfg.DB.URL)
}

// TestApplyBootstrapDefaults_PreservesMonitoring locks in the contract the devenv routing relies on:
// ApplyBootstrapDefaults must not touch a caller-set Monitoring. The component/environment loops set
// Bootstrap.Monitoring before launch, after which ApplyBootstrapDefaults runs again internally; if a
// future default clobbered Monitoring, those values would silently disappear from the bootstrap config.
func TestApplyBootstrapDefaults_PreservesMonitoring(t *testing.T) {
	mon := &monitoring.Config{}

	out := ApplyBootstrapDefaults(BootstrapInput{Monitoring: mon})

	require.Same(t, mon, out.Monitoring, "ApplyBootstrapDefaults must leave a caller-set Monitoring untouched")
}

// TestApplyBootstrapDefaults_NilMonitoringStaysNil confirms ApplyBootstrapDefaults does not invent a
// Monitoring value: nil in means nil out (monitoring not configured), distinct from an explicit config.
func TestApplyBootstrapDefaults_NilMonitoringStaysNil(t *testing.T) {
	out := ApplyBootstrapDefaults(BootstrapInput{})

	require.Nil(t, out.Monitoring, "ApplyBootstrapDefaults must not populate Monitoring when unset")
}
