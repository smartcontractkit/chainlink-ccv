package services

import (
	"fmt"
	"path"
	"strings"

	"github.com/testcontainers/testcontainers-go"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
)

// KeyImportDirContainerPath is where devenv mounts an exported Chainlink node key inside a
// standalone container. The path is devenv's own convention; a real deployment picks its own and
// names it in the bootstrap config's [key_import] section.
const KeyImportDirContainerPath = "/etc/ccv/migration"

const (
	keyImportFileName     = "key.json"
	keyImportPasswordFile = "export-password.txt"
)

// BuildKeyImport turns a host-side export into the bootstrap config section that declares it and
// the container files that back it. Both halves are produced together so the paths named in the
// config and the paths actually mounted cannot drift apart.
//
// Which keystore key the file becomes is not passed in: the bootstrapper works that out from the
// keys the application declares, so there is one fewer thing for the config to get wrong. Neither
// is the export format, which the bootstrapper reads from the file.
//
// expectedID is the address the export must carry. Devenv always sets it: the whole point of the
// migration is that a specific node's identity survives, so importing a different node's key has to
// fail loudly rather than produce a working-looking environment that signs as the wrong operator.
func BuildKeyImport(
	keyHostPath, passwordHostPath, expectedID string,
) (*bootstrap.KeyImport, []testcontainers.ContainerFile, error) {
	if strings.TrimSpace(keyHostPath) == "" {
		return nil, nil, fmt.Errorf("no exported key file provided")
	}
	if strings.TrimSpace(passwordHostPath) == "" {
		return nil, nil, fmt.Errorf("no export password file provided")
	}

	keyContainerPath := path.Join(KeyImportDirContainerPath, keyImportFileName)
	passwordContainerPath := path.Join(KeyImportDirContainerPath, keyImportPasswordFile)

	files := []testcontainers.ContainerFile{
		{HostFilePath: keyHostPath, ContainerFilePath: keyContainerPath, FileMode: 0o600},
		{HostFilePath: passwordHostPath, ContainerFilePath: passwordContainerPath, FileMode: 0o600},
	}
	return &bootstrap.KeyImport{
		Path:         keyContainerPath,
		PasswordPath: passwordContainerPath,
		ExpectedID:   expectedID,
	}, files, nil
}
