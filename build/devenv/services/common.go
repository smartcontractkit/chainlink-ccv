package services

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/testcontainers/testcontainers-go"

	chainsel "github.com/smartcontractkit/chain-selectors"
	ccvblockchain "github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain/canton"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

type Mode string

const (
	Standalone Mode = "standalone"
	CL         Mode = "cl"
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
func GoSourcePathMounts(rootPath, containerDirTarget string) testcontainers.ContainerMounts {
	absRootPath, err := filepath.Abs(rootPath)
	if err != nil {
		fmt.Println("error getting working directory", err)
		return testcontainers.Mounts()
	}

	mounts := make([]testcontainers.ContainerMount, 0)
	mounts = append(mounts,
		testcontainers.BindMount( //nolint:staticcheck // we're still using it...
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
		testcontainers.BindMount( //nolint:staticcheck // we're still using it...
			goModCachePath,
			"/go/pkg/mod",
		),
		testcontainers.BindMount( //nolint:staticcheck // we're still using it...
			goBuildCachePath,
			"/root/.cache/go-build",
		),
	)
	return mounts
}

// ConvertBlockchainOutputsToInfo converts blockchain.Output to a map of chain selector to BlockchainInfo.
func ConvertBlockchainOutputsToInfo(outputs []*ctfblockchain.Output) (map[string]*ccvblockchain.Info, error) {
	infos := make(map[string]*ccvblockchain.Info)
	for _, output := range outputs {
		info := &ccvblockchain.Info{
			ChainID:         output.ChainID,
			Type:            output.Type,
			Family:          output.Family,
			UniqueChainName: output.ContainerName,
			Nodes:           make([]*ccvblockchain.Node, 0, len(output.Nodes)),
		}

		// Convert all nodes
		for _, node := range output.Nodes {
			if node != nil {
				info.Nodes = append(info.Nodes, &ccvblockchain.Node{
					ExternalHTTPUrl: node.ExternalHTTPUrl,
					InternalHTTPUrl: node.InternalHTTPUrl,
					ExternalWSUrl:   node.ExternalWSUrl,
					InternalWSUrl:   node.InternalWSUrl,
				})
			}
		}

		// Add network-specific data (e.g. Canton endpoints)
		if output.NetworkSpecificData != nil {
			info.NetworkSpecificData = &ccvblockchain.NetworkSpecificData{}
			switch output.Family {
			case chainsel.FamilyCanton:
				// TODO: support multiple participants?
				// Different verifiers may connect to different participants, how do we best represent that?
				info.NetworkSpecificData.CantonEndpoints = &canton.Endpoints{
					GRPCLedgerAPIURL: output.NetworkSpecificData.CantonEndpoints.Participants[0].GRPCLedgerAPIURL,
					JWT:              output.NetworkSpecificData.CantonEndpoints.Participants[0].JWT,
				}
			default:
				return nil, fmt.Errorf("unsupported family %s for network specific data", output.Family)
			}
		}

		details, err := chainsel.GetChainDetailsByChainIDAndFamily(output.ChainID, output.Family)
		if err != nil {
			return nil, fmt.Errorf("failed to get chain details for chain %s, family %s: %w", output.ChainID, output.Family, err)
		}

		strSelector := strconv.FormatUint(details.ChainSelector, 10)

		infos[strSelector] = info
	}

	return infos, nil
}
