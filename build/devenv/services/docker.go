package services

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// NormalizeDockerContainerName strips leading slash from Docker inspect names so CLI calls match the container.
func NormalizeDockerContainerName(name string) string {
	return strings.TrimPrefix(strings.TrimSpace(name), "/")
}

// DockerCopyFileToContainer copies a host file into a running container path.
func DockerCopyFileToContainer(ctx context.Context, hostPath, containerName, containerPath string) error {
	containerName = NormalizeDockerContainerName(containerName)
	if hostPath == "" || containerName == "" || containerPath == "" {
		return nil
	}
	dest := containerName + ":" + containerPath
	cmd := exec.CommandContext(ctx, "docker", "cp", hostPath, dest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker cp %s -> %s: %w: %s", hostPath, dest, err, out)
	}
	return nil
}

// RestartContainer restarts a running Docker container by name.
func RestartContainer(ctx context.Context, name string) error {
	name = NormalizeDockerContainerName(name)
	if name == "" {
		return nil
	}
	cmd := exec.CommandContext(ctx, "docker", "restart", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker restart %s: %w: %s", name, err, out)
	}
	return nil
}
