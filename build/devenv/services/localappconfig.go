package services

import (
	"context"
	"fmt"

	"github.com/testcontainers/testcontainers-go"
)

// CopyLocalAppConfigToContainer copies app-config TOML into a running container at containerPath, for
// services running in bootstrap local mode. It is used by the no-JD devenv path, which delivers each
// service's app config after contracts are deployed rather than via a JD job proposal. Copying into
// the container (docker cp) works identically on every Docker host, unlike host-side writes into a
// bind-mounted directory, which do not reliably propagate into an already-running container.
//
// containerPath must sit under a directory that already exists in the image (e.g. directly under
// /etc); CopyToContainer does not create missing parent directories.
func CopyLocalAppConfigToContainer(ctx context.Context, container testcontainers.Container, containerPath, appConfigTOML string) error {
	if container == nil {
		return fmt.Errorf("no running container to deliver local app config to")
	}
	if err := container.CopyToContainer(ctx, []byte(appConfigTOML), containerPath, 0o644); err != nil {
		return fmt.Errorf("failed to copy local app config into container at %s: %w", containerPath, err)
	}
	return nil
}
