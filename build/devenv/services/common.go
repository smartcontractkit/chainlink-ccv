package services

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

// GoCacheMounts returns Go cache mounts depending on platform
// these variables can be found by using
// go env GOCACHE
// go env GOMODCACHE.
func GoCacheMounts() []string {
	homeDir, _ := os.UserHomeDir()
	goHome := os.Getenv("GOPATH")
	if goHome == "" {
		goHome = filepath.Join(homeDir, "go")
	}
	var (
		goModCachePath   string
		goBuildCachePath string
	)

	switch runtime.GOOS {
	case "darwin":
		goModCachePath = filepath.Join(homeDir, "Library", "Caches", "go-build")
		goBuildCachePath = filepath.Join(goHome, "pkg", "mod")
	case "linux":
		goModCachePath = filepath.Join(goHome, "pkg", "mod")
		goBuildCachePath = filepath.Join(homeDir, ".cache", "go-build")
	}

	return []string{
		fmt.Sprintf("%s:/go/pkg/mod", goModCachePath),
		fmt.Sprintf("%s:/root/.cache/go-build", goBuildCachePath),
	}
}
