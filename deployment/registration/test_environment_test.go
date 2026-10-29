package registration

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/domain"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

func newRegistrationTestEnvironment(t *testing.T, client offchain.Client, envKey string) cldf.Environment {
	t.Helper()
	lggr := logger.Test(t)
	getContext := func() context.Context { return t.Context() }
	return cldf.Environment{
		Name:       envKey,
		GetContext: getContext,
		Logger:     lggr,
		Offchain:   client,
		OperationsBundle: operations.NewBundle(
			getContext,
			lggr,
			operations.NewMemoryReporter(),
		),
	}
}

func newRegistrationTestDomain(t *testing.T, key, envKey string) domain.Domain {
	t.Helper()
	d := domain.NewDomain(t.TempDir(), key)
	require.NoError(t, os.MkdirAll(d.EnvDir(envKey).DirPath(), 0o700))
	return d
}

type testNodesFile struct {
	Nodes map[string]map[string]string `json:"nodes"`
}

func readTestNodesFile(t *testing.T, path string) testNodesFile {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var result testNodesFile
	require.NoError(t, json.Unmarshal(data, &result))
	return result
}
