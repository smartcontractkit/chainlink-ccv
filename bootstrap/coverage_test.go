package bootstrap

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

// NewBootstrapper runs the declared-chain coverage check against the checkers families registered
// with chainaccess — bootstrap itself holds no family specifics. These tests wire a fake family
// ("covboot") through the real NewBootstrapper path; local mode keeps the config free of the JD
// infra bundle, and skips chain-type validation, so the fake family needs no other scaffolding.
// Sequential: the checker registration and the captured call state are process-global.
func TestNewBootstrapperDeclaredChainCoverage(t *testing.T) {
	var gotIDs []string
	checkerErr := error(nil)
	chainaccess.RegisterDeclaredChainCoverageChecker("covboot", func(chainIDs []string) error {
		gotIDs = append([]string(nil), chainIDs...)
		return checkerErr
	})

	writeConfig := func(t *testing.T, chainEntries string) (string, string) {
		t.Helper()
		return writeBootstrapConfigFiles(t,
			"app_config_mode = \"local_app_config\"\n"+
				"local_app_config_path = \"/etc/myapp/app.toml\"\n"+chainEntries)
	}

	t.Run("the family's checker runs with its declared IDs at construction", func(t *testing.T) {
		cfgPath, secretsPath := writeConfig(t,
			"[[chains]]\ntype = \"COVBOOT\"\nid = \"1\"\n"+
				"[[chains]]\ntype = \"covboot\"\nid = \"137\"\n")
		_, err := NewBootstrapper("t", &mockServiceFactory{},
			withBootstrapperConfigPath(cfgPath),
			withBootstrapperSecretsPath(secretsPath),
		)
		require.NoError(t, err)
		assert.Equal(t, []string{"1", "137"}, gotIDs,
			"the declared IDs reach the checker grouped under the normalized family, in file order")
	})

	t.Run("a checker failure fails the boot", func(t *testing.T) {
		checkerErr = errors.New("chain 137 is not servable")
		defer func() { checkerErr = nil }()

		cfgPath, secretsPath := writeConfig(t,
			"[[chains]]\ntype = \"COVBOOT\"\nid = \"137\"\n")
		_, err := NewBootstrapper("t", &mockServiceFactory{},
			withBootstrapperConfigPath(cfgPath),
			withBootstrapperSecretsPath(secretsPath),
		)
		require.ErrorContains(t, err, "family covboot")
		require.ErrorContains(t, err, "chain 137 is not servable")
	})

	t.Run("a family without a registered checker is skipped", func(t *testing.T) {
		cfgPath, secretsPath := writeConfig(t,
			"[[chains]]\ntype = \"COVBOOT-UNREGISTERED\"\nid = \"1\"\n")
		_, err := NewBootstrapper("t", &mockServiceFactory{},
			withBootstrapperConfigPath(cfgPath),
			withBootstrapperSecretsPath(secretsPath),
		)
		require.NoError(t, err)
	})

	t.Run("no declared chains: no checker runs", func(t *testing.T) {
		gotIDs = nil
		cfgPath, secretsPath := writeConfig(t, "")
		_, err := NewBootstrapper("t", &mockServiceFactory{},
			withBootstrapperConfigPath(cfgPath),
			withBootstrapperSecretsPath(secretsPath),
		)
		require.NoError(t, err)
		assert.Nil(t, gotIDs)
	})
}

func TestNewBootstrapperDeclaredChainInventoryChecker(t *testing.T) {
	jdConfig := `
[jd]
server_wsrpc_url = "ws://localhost:8080/ws"
server_csa_public_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
[server]
listen_port = 9988
[keystore]
password = "testpassword"
[db]
url = "postgres://localhost:5432/db"
`
	t.Run("JD mode runs the checker before start", func(t *testing.T) {
		cfgPath, secretsPath := writeBootstrapConfigFiles(t, jdConfig)
		called := false
		_, err := NewBootstrapper("t", &mockServiceFactory{},
			withBootstrapperConfigPath(cfgPath),
			withBootstrapperSecretsPath(secretsPath),
			WithDeclaredChainInventoryChecker(func(chains []ChainRegistration) error {
				called = true
				require.Empty(t, chains)
				return errors.New("empty standalone inventory")
			}),
		)
		require.ErrorContains(t, err, "empty standalone inventory")
		require.True(t, called)
	})

	t.Run("local mode retains empty-chain behavior", func(t *testing.T) {
		cfgPath, secretsPath := writeBootstrapConfigFiles(t,
			"app_config_mode = \"local_app_config\"\nlocal_app_config_path = \"/etc/myapp/app.toml\"\n")
		called := false
		_, err := NewBootstrapper("t", &mockServiceFactory{},
			withBootstrapperConfigPath(cfgPath),
			withBootstrapperSecretsPath(secretsPath),
			WithDeclaredChainInventoryChecker(func([]ChainRegistration) error {
				called = true
				return errors.New("must not run")
			}),
		)
		require.NoError(t, err)
		require.False(t, called)
	})
}
