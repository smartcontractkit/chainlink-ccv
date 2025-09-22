package services

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/testcontainers/testcontainers-go"
)

const (
	AppPathInsideContainer = "/app"
)

// CwdSourcePath returns source path for current working directory.
func CwdSourcePath(sourcePath string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(wd), sourcePath), nil
}

// GoSourcePathMounts returns default Golang cache/build-cache and dev-image mounts.
func GoSourcePathMounts(sourcePath, rootPath, containerDirTarget string) testcontainers.ContainerMounts {
	absRootPath, err := filepath.Abs(
		filepath.Join(rootPath, "common"),
	)
	if err != nil {
		fmt.Println("error getting working directory", err)
		return testcontainers.Mounts()
	}

	mounts := make([]testcontainers.ContainerMount, 0)
	mounts = append(mounts,
		testcontainers.BindMount(
			sourcePath,
			testcontainers.ContainerMountTarget(containerDirTarget),
		),
		testcontainers.BindMount(
			absRootPath,
			"/common",
		),
	)
	return mounts
}

// GoCacheMounts returns Go cache mounts depending on platform
// these variables can be found by using
// go env GOCACHE
// go env GOMODCACHE
func GoCacheMounts() testcontainers.ContainerMounts {
	mounts := testcontainers.Mounts()
	homeDir, _ := os.UserHomeDir()
	var (
		goModCachePath   string
		goBuildCachePath string
	)

	switch runtime.GOOS {
	case "darwin":
		goModCachePath = filepath.Join(homeDir, "Library", "Caches", "go-build")
		goBuildCachePath = filepath.Join(homeDir, "go", "pkg", "mod")
	case "linux":
		goModCachePath = filepath.Join(homeDir, "go", "pkg", "mod")
		goBuildCachePath = filepath.Join(homeDir, ".cache", "go-build")
	}
	mounts = append(mounts,
		testcontainers.BindMount(
			goModCachePath,
			"/go/pkg/mod",
		),
		testcontainers.BindMount(
			goBuildCachePath,
			"/root/.cache/go-build",
		),
	)
	return mounts
}
