package services

import (
	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
)

const (
	DefaultAdminConsolePort       = 8105
	DefaultAdminConsolePortTCP    = "8105/tcp"
	DefaultAdminConsoleListenAddr = "0.0.0.0:8105"
	DefaultAdminConsoleConfigPath = "/etc/ccv-admin/config.toml"
	DefaultAdminUIUsername        = "admin"
	DefaultAdminUIPassword        = "admin"
)

type adminConsoleConfig struct {
	ListenAddress string `toml:"listen_address"`
}

// GenerateVerifierSecrets marshals the verifier secrets file with [db], [admin_ui],
// and optional [[aggregators]] entries so devenv and the runtime loader share one schema.
func GenerateVerifierSecrets(dbURL string, aggregators []vsecrets.AggregatorSecret) ([]byte, error) {
	return toml.Marshal(vsecrets.SecretsFile{
		DB:          vsecrets.DBSecrets{URL: dbURL},
		Aggregators: aggregators,
		AdminUI: &vsecrets.AdminUISecret{
			Username: DefaultAdminUIUsername,
			Password: DefaultAdminUIPassword,
		},
	})
}

// GenerateAdminConsoleConfig marshals the in-process admin console config for container port-forwarding.
func GenerateAdminConsoleConfig() ([]byte, error) {
	return toml.Marshal(adminConsoleConfig{
		ListenAddress: DefaultAdminConsoleListenAddr,
	})
}
