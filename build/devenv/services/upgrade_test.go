package services

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

func TestUpgradeContainer(t *testing.T) {
	if testing.Short() {
		t.Skip("needs docker")
	}
	ctx := t.Context()
	name := "upgrade-test-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))

	pullImage(ctx, t, "redis:7-alpine")
	pullImage(ctx, t, "nginx:alpine")

	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("key = 1\n"), 0o600))
	mountedPath := filepath.Join(t.TempDir(), "mounted.toml")
	require.NoError(t, os.WriteFile(mountedPath, []byte("mounted = true\n"), 0o644))

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:      "redis:7-alpine",
			Name:       name,
			Entrypoint: []string{"sleep", "3600"},
			Env:        map[string]string{"SERVICE_SETTING": "kept"},
			HostConfigModifier: func(h *container.HostConfig) {
				h.Binds = append(h.Binds, mountedPath+":/etc/upgrade-test/mounted.toml:ro")
			},
			Files: []testcontainers.ContainerFile{
				{HostFilePath: cfgPath, ContainerFilePath: "/etc/upgrade-test/config.toml", FileMode: 0o644},
			},
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		removeContainer(name)
		removeContainer(name + "-pre-upgrade")
	})

	// A file that the service writes at run time must not be carried over.
	code, _ := execIn(ctx, t, c.GetContainerID(), "touch", "/tmp/runtime-file")
	require.Equal(t, 0, code)
	// A listed file that devenv copies in after start, as local.profile does, must be carried over.
	code, _ = execIn(ctx, t, c.GetContainerID(), "sh", "-c", "echo 'app = 1' > /etc/upgrade-test/app.toml")
	require.Equal(t, 0, code)

	same, err := RunsImage(ctx, name, "nginx:alpine")
	require.NoError(t, err)
	require.False(t, same)

	err = UpgradeContainer(ctx, name, "nginx:alpine", nil)
	require.ErrorContains(t, err, "not in the upgrade file list")
	require.ErrorContains(t, err, "/etc/upgrade-test/config.toml")

	withMissing := []UpgradeFile{
		{Pattern: "/etc/upgrade-test/*.toml", Policy: Optional},
		{Pattern: "/etc/upgrade-test/absent.toml", Policy: Required},
	}
	require.ErrorContains(t, UpgradeContainer(ctx, name, "nginx:alpine", withMissing), "required file /etc/upgrade-test/absent.toml is missing")

	running, err := IsRunning(ctx, name)
	require.NoError(t, err)
	require.True(t, running, "a failed check leaves the old container running")

	list := []UpgradeFile{
		{Pattern: "/etc/upgrade-test/config.toml", Policy: Required},
		{Pattern: "/etc/upgrade-test/app.toml", Policy: Optional},
	}
	require.NoError(t, UpgradeContainer(ctx, name, "nginx:alpine", list))

	same, err = RunsImage(ctx, name, "nginx:alpine")
	require.NoError(t, err)
	require.True(t, same)

	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	require.NoError(t, err)
	defer cli.Close()

	upgraded, err := cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	require.NoError(t, err)
	require.Equal(t, "nginx:alpine", upgraded.Container.Config.Image)
	require.True(t, upgraded.Container.State.Running)
	require.Contains(t, upgraded.Container.Config.Env, "SERVICE_SETTING=kept")
	for _, e := range upgraded.Container.Config.Env {
		require.False(t, strings.HasPrefix(e, "REDIS_"), "old image env %q is dropped", e)
	}

	old, err := cli.ContainerInspect(ctx, name+"-pre-upgrade", client.ContainerInspectOptions{})
	require.NoError(t, err)
	require.False(t, old.Container.State.Running)

	code, out := execIn(ctx, t, upgraded.Container.ID, "cat", "/etc/upgrade-test/config.toml")
	require.Equal(t, 0, code)
	require.Equal(t, "key = 1\n", out, "devenv-copied file is carried over")
	code, out = execIn(ctx, t, upgraded.Container.ID, "cat", "/etc/upgrade-test/app.toml")
	require.Equal(t, 0, code)
	require.Equal(t, "app = 1\n", out, "listed file copied in after start is carried over")
	code, out = execIn(ctx, t, upgraded.Container.ID, "cat", "/etc/upgrade-test/mounted.toml")
	require.Equal(t, 0, code)
	require.Equal(t, "mounted = true\n", out, "bind mount is kept")
	code, _ = execIn(ctx, t, upgraded.Container.ID, "test", "-f", "/tmp/runtime-file")
	require.NotEqual(t, 0, code, "run-time file is not carried over")
}

// execIn runs cmd in the container and returns its exit code and output.
func execIn(ctx context.Context, t *testing.T, id string, cmd ...string) (int, string) {
	t.Helper()
	code, out, err := Exec(ctx, id, cmd...)
	require.NoError(t, err)
	return code, out
}

// pullImage pulls the image, so that the test also works on a Docker daemon that does not have it.
func pullImage(ctx context.Context, t *testing.T, image string) {
	t.Helper()
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	require.NoError(t, err)
	defer cli.Close()
	resp, err := cli.ImagePull(ctx, image, client.ImagePullOptions{})
	require.NoError(t, err)
	defer resp.Close()
	require.NoError(t, resp.Wait(ctx))
}

func removeContainer(name string) {
	ctx := context.Background()
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		return
	}
	defer cli.Close()
	_, _ = cli.ContainerRemove(ctx, name, client.ContainerRemoveOptions{Force: true})
}

func TestImageWithTag(t *testing.T) {
	require.Equal(t, "indexer:head", ImageWithTag("indexer:latest", "head"))
	require.Equal(t, "indexer:head", ImageWithTag("indexer", "head"))
	require.Equal(t, "localhost:5000/ccv/indexer:head", ImageWithTag("localhost:5000/ccv/indexer:v1", "head"))
	require.Equal(t, "indexer:head", ImageWithTag("indexer:v1@sha256:abc", "head"))
}
