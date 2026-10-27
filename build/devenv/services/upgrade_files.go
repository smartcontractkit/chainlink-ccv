package services

import (
	"os"
	"path"

	aggregator "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/secrets"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
)

// UpgradePolicy says what an upgrade does with a file that devenv copied into a container.
type UpgradePolicy int

const (
	// Required files are copied; the upgrade fails if the old container does not have one.
	Required UpgradePolicy = iota
	// Optional files are copied when the old container has them.
	Optional
	// NotCarried files are left behind, as in a real upgrade. The service must not need them after its first start.
	NotCarried
)

// UpgradeFile is a file, or a path.Match pattern, that devenv copies into a service container before start.
type UpgradeFile struct {
	Pattern string
	Policy  UpgradePolicy
}

// UpgradeFiles returns the files that devenv copies into the containers of the image repository.
// Mounted files are not listed: the upgraded container gets the same mounts.
func UpgradeFiles(repo string) []UpgradeFile {
	files := []UpgradeFile{
		{Pattern: "/etc/ssl/certs/ca-certificates.crt", Policy: Optional}, // set only with a TLS CA file
		// The service imports these keys on first start only; after that, the keys are in its database.
		{Pattern: path.Join(KeyImportDirContainerPath, "*"), Policy: NotCarried},
		// The EVM chain family modifier copies its config in (evm/registration.go); other families do not.
		{Pattern: evmconfig.DefaultEVMConfigPath, Policy: Optional},
	}
	if p := os.Getenv(gcpCredentialEnvVar); p != "" {
		files = append(files, UpgradeFile{Pattern: p, Policy: Optional})
	}

	switch repo {
	case "indexer":
		files = append(files,
			UpgradeFile{Pattern: path.Join(IndexerConfigDirContainer, "config.toml"), Policy: Required},
			UpgradeFile{Pattern: path.Join(IndexerConfigDirContainer, "generated.toml"), Policy: Required},
			UpgradeFile{Pattern: path.Join(IndexerConfigDirContainer, "secrets.toml"), Policy: Required},
		)
	case "aggregator":
		files = append(files,
			UpgradeFile{Pattern: aggregator.DefaultConfigFile, Policy: Required},
			// The generated config name has the instance name: aggregator-<instance>-generated.toml.
			UpgradeFile{Pattern: path.Join(path.Dir(aggregator.DefaultConfigFile), "aggregator-*-generated.toml"), Policy: Required},
			UpgradeFile{Pattern: secrets.DefaultSecretsPath, Policy: Required},
		)
	}
	return files
}

func matchUpgradeFile(list []UpgradeFile, p string) (UpgradeFile, bool) {
	for _, f := range list {
		if ok, _ := path.Match(f.Pattern, p); ok {
			return f, true
		}
	}
	return UpgradeFile{}, false
}
