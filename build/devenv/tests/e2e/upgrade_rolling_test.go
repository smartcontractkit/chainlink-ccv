package e2e

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	burn_mint_erc20_with_drip_v1_5 "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/burn_mint_erc20_with_drip"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi/basic"
)

// UpgradeImageTagEnv is the tag of the images to upgrade to. The environment must run the images to upgrade from.
const UpgradeImageTagEnv = "CCV_UPGRADE_IMAGE_TAG"

// UpgradeFromImageTagEnv is the tag of the images that the environment must run before the upgrade. Default: latest.
const UpgradeFromImageTagEnv = "CCV_UPGRADE_FROM_IMAGE_TAG"

// rolloutOrder is the order in which a deployment upgrades the services, by image repository.
var rolloutOrder = []string{"indexer", "aggregator", "verifier", "token-verifier", "executor"}

// upgradeSettleTime is how long a container must stay up after an upgrade before the test sends a message.
const upgradeSettleTime = 10 * time.Second

// TestE2EUpgrade_HappyPath upgrades each service container to the image tag in CCV_UPGRADE_IMAGE_TAG, one at a
// time and in rollout order. The databases, keys, and chains stay. A message must execute before the upgrade,
// after each container upgrade (with mixed versions), and at the end.
func TestE2EUpgrade_HappyPath(t *testing.T) {
	env := newUpgradeEnv(t, false)

	t.Run("before upgrade", env.happyPath)
	for _, s := range env.steps {
		env.swap(t, "after upgrading "+s.name, s.name, s.toImage, s.repo, services.UpgradeContainer)
	}
	t.Run("after full upgrade", env.happyPath)
}

// TestE2ERollback_HappyPath starts on the images to upgrade to and rolls each service back to the image to upgrade
// from, one at a time and in reverse rollout order. The old images must run on the schema and data of the new images.
func TestE2ERollback_HappyPath(t *testing.T) {
	env := newUpgradeEnv(t, true)

	t.Run("before rollback", env.happyPath)
	for _, s := range slices.Backward(env.steps) {
		env.swap(t, "after rolling back "+s.name, s.name, s.fromImage, s.repo, services.RollbackContainer)
	}
	t.Run("after full rollback", env.happyPath)
}

// upgradeStep is one service container and the images it moves between.
type upgradeStep struct{ name, repo, fromImage, toImage string }

// upgradeEnv is the running environment and the containers to swap, in rollout order.
type upgradeEnv struct {
	ctx       context.Context
	in        *ccv.Cfg
	lib       ccv.Lib
	src, dest uint64
	proxies   map[string]string
	steps     []upgradeStep
	// evmSrc and evmDest are set if the environment has two EVM chains, which the token transfers use.
	evmChains       map[uint64]cciptestinterfaces.CCIP17
	evmSrc, evmDest uint64
}

// newUpgradeEnv checks that each service runs its start image and that its files can be carried over.
// The start image is the image to upgrade to if onTo is set, else the image to upgrade from.
func newUpgradeEnv(t *testing.T, onTo bool) *upgradeEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	tag := os.Getenv(UpgradeImageTagEnv)
	if tag == "" {
		t.Skipf("%s is not set", UpgradeImageTagEnv)
	}
	fromTag := os.Getenv(UpgradeFromImageTagEnv)
	if fromTag == "" {
		fromTag = "latest"
	}
	ctx := ccv.Plog.WithContext(t.Context())

	lib, err := ccv.NewLibFromCCVEnv(&ccv.Plog, GetSmokeTestConfig())
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains for this test in the environment")

	in, err := ccv.LoadOutput[ccv.Cfg](GetSmokeTestConfig())
	require.NoError(t, err)

	env := &upgradeEnv{
		ctx:     ctx,
		in:      in,
		lib:     lib,
		src:     chains[0].ChainSelector(),
		dest:    chains[1].ChainSelector(),
		proxies: aggregatorProxies(in),
	}
	evmLib, err := ccv.NewLibFromCCVEnv(&ccv.Plog, GetSmokeTestConfig(), chain_selectors.FamilyEVM)
	require.NoError(t, err)
	evmChains, err := evmLib.Chains(ctx)
	require.NoError(t, err)
	if len(evmChains) >= 2 {
		env.evmChains, err = evmLib.ChainsMap(ctx)
		require.NoError(t, err)
		env.evmSrc, env.evmDest = evmChains[0].Details.ChainSelector, evmChains[1].Details.ChainSelector
	}
	for _, repo := range rolloutOrder {
		names, err := services.RunningContainersByImage(ctx, repo)
		require.NoError(t, err)
		for _, name := range names {
			image := services.ImageWithTag(repo, tag)
			fromImage := services.ImageWithTag(repo, fromTag)
			start := fromImage
			if onTo {
				start = image
			}
			runsStart, err := services.RunsImage(ctx, name, start)
			require.NoError(t, err)
			require.True(t, runsStart, "%s does not run %s: start the environment with 'just upgrade-test' or 'just rollback-test'", name, start)
			unchanged, err := services.SameImage(ctx, fromImage, image)
			require.NoError(t, err)
			if unchanged {
				t.Logf("%s: %s and %s are the same image, so its swap is a restart on the existing data", name, fromImage, image)
			}
			require.NoError(t, services.CheckUpgradeFiles(ctx, name, services.UpgradeFiles(repo)))
			env.steps = append(env.steps, upgradeStep{name: name, repo: repo, fromImage: fromImage, toImage: image})
		}
	}
	require.NotEmpty(t, env.steps, "no service container found to upgrade")
	return env
}

// happyPath sends a basic message, then a USDC and a Lombard transfer, which need the token verifier.
func (e *upgradeEnv) happyPath(t *testing.T) {
	t.Helper()
	runHappyPath(t, e.lib, e.src, e.dest)
	e.tokenPath(t)
}

// tokenPath sends one USDC and one Lombard transfer between the first two EVM chains, if the environment has them.
func (e *upgradeEnv) tokenPath(t *testing.T) {
	t.Helper()
	if e.evmChains == nil {
		t.Log("fewer than 2 EVM chains: no token transfer")
		return
	}
	src, dest := e.evmChains[e.evmSrc], e.evmChains[e.evmDest]
	// A swap restarts the aggregator and the indexer, so make new clients for each step.
	l := zerolog.Ctx(e.ctx)
	aggregator := SetupAggregatorClients(t, e.ctx, e.in)[common.DefaultCommitteeVerifierQualifier]
	indexer := SetupIndexerMonitor(t, e.ctx, e.lib)

	if e.hasToken(e.evmSrc, "") && e.hasToken(e.evmDest, "") {
		t.Run("USDC", func(t *testing.T) {
			runUSDCTestCase(t, e.ctx, l, e.in, src, dest, e.evmSrc, e.evmDest, e.evmChains, aggregator, indexer, usdcEOACase(t, dest))
		})
	} else {
		t.Log("no USDC token in the environment: no USDC transfer")
	}
	if e.hasToken(e.evmSrc, common.LombardContractsQualifier) && e.hasToken(e.evmDest, common.LombardContractsQualifier) {
		t.Run("Lombard", func(t *testing.T) {
			runLombardTestCase(t, e.ctx, l, e.in, src, dest, e.evmSrc, e.evmDest, e.evmChains, aggregator, indexer, lombardEOACase(t, dest))
		})
	} else {
		t.Log("no Lombard token in the environment: no Lombard transfer")
	}
}

// hasToken reports if the datastore has the test token with the qualifier: "" for USDC, Lombard for Lombard.
func (e *upgradeEnv) hasToken(selector uint64, qualifier string) bool {
	_, err := e.in.CLDF.DataStore.Addresses().Get(datastore.NewAddressRefKey(selector,
		datastore.ContractType(burn_mint_erc20_with_drip_v1_5.ContractType),
		semver.MustParse(burn_mint_erc20_with_drip_v1_5.Deploy.Version()), qualifier))
	return err == nil
}

// settle waits until the swapped container stays up, then makes the aggregator proxy resolve it again.
func (e *upgradeEnv) settle(t *testing.T, name string) {
	t.Helper()
	requireStaysRunning(t, e.ctx, name, upgradeSettleTime)
	if proxy, ok := e.proxies[name]; ok {
		reloadProxy(t, e.ctx, proxy)
	}
}

// swap replaces one container in a subtest, then sends a message. The test stops at the first failed swap.
func (e *upgradeEnv) swap(t *testing.T, step, name, image, repo string, replace func(context.Context, string, string, []services.UpgradeFile) error) {
	t.Helper()
	ok := t.Run(step, func(t *testing.T) {
		require.NoError(t, replace(e.ctx, name, image, services.UpgradeFiles(repo)))
		e.settle(t, name)
		e.happyPath(t)
	})
	require.True(t, ok, "rollout stopped at %s", name)
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

// aggregatorProxies maps each aggregator container to its nginx TLS proxy container.
func aggregatorProxies(in *ccv.Cfg) map[string]string {
	proxies := make(map[string]string)
	for _, agg := range in.Aggregator {
		if agg != nil && agg.Out != nil && agg.Out.NginxContainerName != "" {
			proxies[agg.Out.AggregatorContainerName] = agg.Out.NginxContainerName
		}
	}
	return proxies
}

// reloadProxy makes nginx resolve the aggregator host again: it resolves grpc_pass only at load, and the upgraded
// aggregator can have a new IP.
func reloadProxy(t *testing.T, ctx context.Context, proxy string) {
	t.Helper()
	code, out, err := services.Exec(ctx, proxy, "nginx", "-s", "reload")
	require.NoError(t, err)
	require.Equal(t, 0, code, "reload %s: %s", proxy, out)
}
