package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi/basic"
)

// UpgradeImageTagEnv is the tag of the images to upgrade to. The environment must run the images to upgrade from.
const UpgradeImageTagEnv = "CCV_UPGRADE_IMAGE_TAG"

// rolloutOrder is the order in which a deployment upgrades the services, by image repository.
var rolloutOrder = []string{"indexer", "aggregator", "verifier", "token-verifier", "executor"}

// upgradeSettleTime is how long a container must stay up after an upgrade before the test sends a message.
const upgradeSettleTime = 10 * time.Second

// TestE2EUpgrade_HappyPath upgrades each service container to the image tag in CCV_UPGRADE_IMAGE_TAG, one at a
// time and in rollout order. The databases, keys, and chains stay. A message must execute before the upgrade,
// after each container upgrade (with mixed versions), and at the end.
func TestE2EUpgrade_HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	tag := os.Getenv(UpgradeImageTagEnv)
	if tag == "" {
		t.Skipf("%s is not set", UpgradeImageTagEnv)
	}
	ctx := ccv.Plog.WithContext(t.Context())

	lib, err := ccv.NewLibFromCCVEnv(&ccv.Plog, GetSmokeTestConfig())
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains for this test in the environment")
	src, dest := chains[0].ChainSelector(), chains[1].ChainSelector()

	happyPath := func(t *testing.T) {
		t.Helper()
		runHappyPath(t, lib, src, dest)
	}

	type upgrade struct{ name, repo, image string }
	var upgrades []upgrade
	for _, repo := range rolloutOrder {
		names, err := services.RunningContainersByImage(ctx, repo)
		require.NoError(t, err)
		for _, name := range names {
			image := services.ImageWithTag(repo, tag)
			same, err := services.RunsImage(ctx, name, image)
			require.NoError(t, err)
			require.False(t, same, "%s already runs %s: start the environment on the images to upgrade from (see 'just upgrade-test')", name, image)
			require.NoError(t, services.CheckUpgradeFiles(ctx, name, services.UpgradeFiles(repo)))
			upgrades = append(upgrades, upgrade{name: name, repo: repo, image: image})
		}
	}
	require.NotEmpty(t, upgrades, "no service container found to upgrade")

	t.Run("before upgrade", happyPath)

	for _, u := range upgrades {
		ok := t.Run("after upgrading "+u.name, func(t *testing.T) {
			require.NoError(t, services.UpgradeContainer(ctx, u.name, u.image, services.UpgradeFiles(u.repo)))
			requireStaysRunning(t, ctx, u.name, upgradeSettleTime)
			happyPath(t)
		})
		require.True(t, ok, "rollout stopped at %s", u.name)
	}

	t.Run("after full upgrade", happyPath)
}

// runHappyPath sends the first basic message case that the environment supports and waits until it executes.
func runHappyPath(t *testing.T, lib ccv.Lib, src, dest uint64) {
	t.Helper()
	ctx := ccv.Plog.WithContext(t.Context())
	for _, tc := range basic.All(lib, src, dest, basic.Args{Send: tcapi.SendArgs{}}) {
		if !tc.HavePrerequisites(ctx) {
			continue
		}
		_, err := tc.Run(ctx)
		require.NoError(t, err, "test case %s", tc.Name())
		return
	}
	t.Fatal("no basic test case has its prerequisites in this environment")
}

// requireStaysRunning fails if the container stops within d, for example because the new image cannot start on the old data.
func requireStaysRunning(t *testing.T, ctx context.Context, name string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		running, err := services.IsRunning(ctx, name)
		require.NoError(t, err)
		require.True(t, running, "%s stopped after the upgrade; see its logs", name)
		time.Sleep(time.Second)
	}
}
