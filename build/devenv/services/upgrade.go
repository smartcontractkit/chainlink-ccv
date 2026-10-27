package services

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
)

// UpgradeContainer replaces a running container with one from image, as a rolling upgrade does.
// The new container keeps the name, env, ports, network aliases, mounts, and the files in the list that devenv copied in.
// The old container is stopped and renamed to <name>-pre-upgrade, so its logs stay available.
func UpgradeContainer(ctx context.Context, name, image string, list []UpgradeFile) error {
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		return fmt.Errorf("docker client: %w", err)
	}
	defer cli.Close()

	inspect, err := cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err != nil {
		return fmt.Errorf("inspect %s: %w", name, err)
	}
	old := inspect.Container
	oldImage, err := cli.ImageInspect(ctx, old.Image)
	if err != nil {
		return fmt.Errorf("inspect image of %s: %w", name, err)
	}

	files, err := carriedFiles(ctx, cli.Client, old, list)
	if err != nil {
		return fmt.Errorf("files of %s: %w", name, err)
	}

	backupName := name + "-pre-upgrade"
	if _, err := cli.ContainerRename(ctx, old.ID, client.ContainerRenameOptions{NewName: backupName}); err != nil {
		return fmt.Errorf("rename %s: %w", name, err)
	}
	rollback := func() {
		_, _ = cli.ContainerRename(ctx, old.ID, client.ContainerRenameOptions{NewName: name})
		_, _ = cli.ContainerStart(ctx, old.ID, client.ContainerStartOptions{})
	}

	created, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:             name,
		Config:           upgradedConfig(old.Config, oldImage.Config.Env, oldImage.Config.Cmd, oldImage.Config.Entrypoint, oldImage.Config.Labels, image),
		HostConfig:       old.HostConfig,
		NetworkingConfig: upgradedNetworking(old),
	})
	if err != nil {
		rollback()
		return fmt.Errorf("create %s from %s: %w", name, image, err)
	}
	removeNew := func() {
		_, _ = cli.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{Force: true})
	}

	for _, f := range files {
		if _, err := cli.CopyToContainer(ctx, created.ID, client.CopyToContainerOptions{DestinationPath: "/", Content: bytes.NewReader(f.tar)}); err != nil {
			removeNew()
			rollback()
			return fmt.Errorf("copy %s into new %s: %w", f.path, name, err)
		}
	}

	if _, err := cli.ContainerStop(ctx, old.ID, client.ContainerStopOptions{}); err != nil {
		removeNew()
		rollback()
		return fmt.Errorf("stop old %s: %w", name, err)
	}
	if _, err := cli.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		removeNew()
		rollback()
		return fmt.Errorf("start %s from %s: %w", name, image, err)
	}
	return nil
}

// upgradedConfig keeps the settings of the container, but not the defaults of its old image, so the new image defaults apply.
func upgradedConfig(old *container.Config, imageEnv, imageCmd, imageEntrypoint []string, imageLabels map[string]string, image string) *container.Config {
	cfg := *old
	cfg.Image = image
	cfg.Hostname = ""
	cfg.Env = slices.DeleteFunc(slices.Clone(old.Env), func(e string) bool { return slices.Contains(imageEnv, e) })
	if slices.Equal(old.Cmd, imageCmd) {
		cfg.Cmd = nil
	}
	if slices.Equal(old.Entrypoint, imageEntrypoint) {
		cfg.Entrypoint = nil
	}
	cfg.Labels = maps.Clone(old.Labels)
	maps.DeleteFunc(cfg.Labels, func(k, v string) bool { return imageLabels[k] == v })
	return &cfg
}

// upgradedNetworking keeps the networks and the user-set aliases of the container.
func upgradedNetworking(old container.InspectResponse) *network.NetworkingConfig {
	endpoints := make(map[string]*network.EndpointSettings)
	if old.NetworkSettings == nil {
		return &network.NetworkingConfig{EndpointsConfig: endpoints}
	}
	shortID := old.ID[:min(12, len(old.ID))]
	for name, es := range old.NetworkSettings.Networks {
		aliases := slices.DeleteFunc(slices.Clone(es.Aliases), func(a string) bool { return a == shortID })
		endpoints[name] = &network.EndpointSettings{Aliases: aliases}
	}
	return &network.NetworkingConfig{EndpointsConfig: endpoints}
}

type carriedFile struct {
	path string
	tar  []byte // one entry, named with the full path, so that extraction at "/" creates the parent directories
}

// carriedFiles returns the files of the list to copy into the new container, as tar archives.
// It fails if devenv copied a file in before start that the list does not name, or if a required file is missing.
func carriedFiles(ctx context.Context, cli *client.Client, old container.InspectResponse, list []UpgradeFile) ([]carriedFile, error) {
	startedAt, err := time.Parse(time.RFC3339Nano, old.State.StartedAt)
	if err != nil {
		return nil, fmt.Errorf("parse start time %q: %w", old.State.StartedAt, err)
	}
	diff, err := cli.ContainerDiff(ctx, old.ID, client.ContainerDiffOptions{})
	if err != nil {
		return nil, err
	}

	// Mounted paths come back through HostConfig; copying over them fails with "device or resource busy".
	var mounts []string
	for _, m := range old.Mounts {
		mounts = append(mounts, m.Destination)
	}
	underMount := func(path string) bool {
		return slices.ContainsFunc(mounts, func(dest string) bool { return path == dest || strings.HasPrefix(path, dest+"/") })
	}

	var files []carriedFile
	var unlisted []string
	matched := make(map[string]bool)
	for _, change := range diff.Changes {
		if change.Kind != container.ChangeAdd && change.Kind != container.ChangeModify || underMount(change.Path) {
			continue
		}
		// Stat first: a copy of a changed directory makes Docker archive all of it.
		st, err := cli.ContainerStatPath(ctx, old.ID, client.ContainerStatPathOptions{Path: change.Path})
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", change.Path, err)
		}
		// Files written after start are run-time state, which a real upgrade also loses.
		if !st.Stat.Mode.IsRegular() || !st.Stat.Mtime.Before(startedAt) {
			continue
		}
		entry, ok := matchUpgradeFile(list, change.Path)
		if !ok {
			unlisted = append(unlisted, change.Path)
			continue
		}
		matched[entry.Pattern] = true
		if entry.Policy == NotCarried {
			continue
		}
		res, err := cli.CopyFromContainer(ctx, old.ID, client.CopyFromContainerOptions{SourcePath: change.Path})
		if err != nil {
			return nil, fmt.Errorf("copy %s: %w", change.Path, err)
		}
		b, err := rootedTar(res.Content, change.Path)
		_ = res.Content.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", change.Path, err)
		}
		files = append(files, carriedFile{path: change.Path, tar: b})
	}

	if len(unlisted) > 0 {
		return nil, fmt.Errorf("devenv copied files that are not in the upgrade file list (services/upgrade_files.go): %v", unlisted)
	}
	for _, f := range list {
		if f.Policy == Required && !matched[f.Pattern] {
			return nil, fmt.Errorf("required file %s is missing", f.Pattern)
		}
	}
	return files, nil
}

// rootedTar rewrites the single-file archive from CopyFromContainer so that its entry has the full path.
func rootedTar(r io.Reader, path string) ([]byte, error) {
	tr := tar.NewReader(r)
	hdr, err := tr.Next()
	if err != nil {
		return nil, err
	}
	hdr.Name = strings.TrimPrefix(path, "/")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := io.Copy(tw, tr); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RunningContainersByImage returns the names of running containers whose image repository is repo, sorted.
func RunningContainersByImage(ctx context.Context, repo string) ([]string, error) {
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	defer cli.Close()
	list, err := cli.ContainerList(ctx, client.ContainerListOptions{})
	if err != nil {
		return nil, err
	}
	var names []string
	for _, c := range list.Items {
		if imageRepo(c.Image) != repo || len(c.Names) == 0 {
			continue
		}
		names = append(names, strings.TrimPrefix(c.Names[0], "/"))
	}
	slices.Sort(names)
	return names, nil
}

// ImageWithTag returns image with its tag replaced by tag, for example indexer:latest -> indexer:head.
func ImageWithTag(image, tag string) string {
	return imageRepo(image) + ":" + tag
}

func imageRepo(image string) string {
	image, _, _ = strings.Cut(image, "@")
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		return image[:i]
	}
	return image
}

// IsRunning reports whether the container with the given name is running.
func IsRunning(ctx context.Context, name string) (bool, error) {
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		return false, fmt.Errorf("docker client: %w", err)
	}
	defer cli.Close()
	res, err := cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err != nil {
		return false, err
	}
	return res.Container.State != nil && res.Container.State.Running, nil
}

// RunsImage reports whether the container runs the same image ID as the image reference.
func RunsImage(ctx context.Context, name, image string) (bool, error) {
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		return false, fmt.Errorf("docker client: %w", err)
	}
	defer cli.Close()
	c, err := cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err != nil {
		return false, err
	}
	img, err := cli.ImageInspect(ctx, image)
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", image, err)
	}
	return c.Container.Image == img.ID, nil
}

// CheckUpgradeFiles fails if the container files do not agree with the list. It does not change the container.
func CheckUpgradeFiles(ctx context.Context, name string, list []UpgradeFile) error {
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		return fmt.Errorf("docker client: %w", err)
	}
	defer cli.Close()
	inspect, err := cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err != nil {
		return fmt.Errorf("inspect %s: %w", name, err)
	}
	if _, err := carriedFiles(ctx, cli.Client, inspect.Container, list); err != nil {
		return fmt.Errorf("files of %s: %w", name, err)
	}
	return nil
}

// SameImage reports whether two image references have the same image ID.
func SameImage(ctx context.Context, a, b string) (bool, error) {
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		return false, fmt.Errorf("docker client: %w", err)
	}
	defer cli.Close()
	imgA, err := cli.ImageInspect(ctx, a)
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", a, err)
	}
	imgB, err := cli.ImageInspect(ctx, b)
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", b, err)
	}
	return imgA.ID == imgB.ID, nil
}
