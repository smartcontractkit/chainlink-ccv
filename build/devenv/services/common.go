package services

import (
	_ "embed"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"

	"github.com/testcontainers/testcontainers-go"
)

type Mode string

const (
	Standalone Mode = "standalone"
	CL         Mode = "cl"
	// Local runs the service standalone without a Job Distributor: the bootstrapper reads the app
	// config from a mounted file (app_config_mode = "local_app_config" in the bootstrap config.toml).
	// Used by the CCV starter kit and local testing where JD is unavailable.
	Local Mode = "local"
)

const (
	AppPathInsideContainer = "/app"

	// HostGatewayExtraHost maps host.docker.internal to the host gateway so containers can
	// resolve it on Linux Docker hosts, where the name has no default mapping; services reach
	// the observability stack's published OTLP port through it. Docker Desktop already maps
	// the name, so appending it there is harmless.
	HostGatewayExtraHost = "host.docker.internal:host-gateway"
)

// TelemetryAttrs copies base telemetry attributes and adds OTel service identity:
// service.name for the service type and service.instance.id for the container name.
// The fresh map prevents per-service writes from aliasing the shared config.
func TelemetryAttrs(base map[string]string, service, instance string) map[string]string {
	attrs := make(map[string]string, len(base)+2)
	maps.Copy(attrs, base)
	attrs["service.name"] = service
	if instance != "" {
		attrs["service.instance.id"] = instance
	}
	return attrs
}

// awsCredentialEnvVars are the standard AWS SDK environment variables that carry credentials and
// region. Forwarding these from the host lets a container reach AWS (e.g. KMS) via the default
// credential chain without a mounted profile. Session-token creds (SSO/STS) are short-lived, so a
// forwarded set expires with the host session.
var awsCredentialEnvVars = []string{
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AWS_REGION",
	"AWS_DEFAULT_REGION",
}

// ForwardedAWSEnv returns the subset of the standard AWS environment variables that are set on the
// host, as a map suitable for a container's Env. Only variables that are present (and non-empty) are
// included, so callers can merge the result unconditionally. Returns an empty (non-nil) map when the
// host has no AWS environment configured.
func ForwardedAWSEnv() map[string]string {
	env := make(map[string]string, len(awsCredentialEnvVars))
	for _, key := range awsCredentialEnvVars {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			env[key] = v
		}
	}
	return env
}

// gcpCredentialEnvVar is the standard Google Cloud env var carrying the path to a service-account
// JSON key, which Application Default Credentials reads to authenticate (the GCP analog of the AWS
// credential chain).
const gcpCredentialEnvVar = "GOOGLE_APPLICATION_CREDENTIALS"

// ForwardedGCPCreds returns the environment and container files needed for a container to reach
// Google Cloud KMS via Application Default Credentials, mirroring ForwardedAWSEnv for AWS. When the
// host sets GOOGLE_APPLICATION_CREDENTIALS, the env var is forwarded and the referenced key file is
// mounted into the container at the same absolute path so ADC finds it. Returns an empty (non-nil)
// env map and no files when the host has no GCP credentials configured, so callers can merge
// unconditionally.
func ForwardedGCPCreds() (env map[string]string, files []testcontainers.ContainerFile) {
	env = make(map[string]string)
	if p, ok := os.LookupEnv(gcpCredentialEnvVar); ok && p != "" {
		env[gcpCredentialEnvVar] = p
		files = append(files, testcontainers.ContainerFile{
			HostFilePath:      p,
			ContainerFilePath: p,
			FileMode:          0o644,
		})
	}
	return env, files
}

// CwdSourcePath returns source path for current working directory.
func CwdSourcePath(sourcePath string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(wd), sourcePath), nil
}

// GoSourcePathMounts returns default Golang cache/build-cache and dev-image mounts.
func GoSourcePathMounts(rootPath, containerDirTarget string) testcontainers.ContainerMounts {
	absRootPath, err := filepath.Abs(rootPath)
	if err != nil {
		fmt.Println("error getting working directory", err)
		return testcontainers.Mounts()
	}

	mounts := make([]testcontainers.ContainerMount, 0, 1)
	mounts = append(mounts,
		testcontainers.BindMount(
			absRootPath,
			testcontainers.ContainerMountTarget(containerDirTarget),
		),
	)
	return mounts
}

// GoCacheMounts returns Go cache mounts depending on platform
// these variables can be found by using
// go env GOCACHE
// go env GOMODCACHE.
func GoCacheMounts() testcontainers.ContainerMounts {
	mounts := testcontainers.Mounts()
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
