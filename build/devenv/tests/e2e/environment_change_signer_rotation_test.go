package e2e

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	offchainshared "github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/offchain/shared"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/verifiercli"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	nodesetpkg "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

const rotationFakeNOPAlias = "nop-rotation-old-key"

func snapshotEnvironmentTopologyCleanup(t *testing.T, h *environmentChangeReconcileHarness) {
	t.Helper()
	topoSnap, err := toml.Marshal(*h.Cfg.EnvironmentTopology)
	require.NoError(t, err)
	t.Cleanup(func() {
		var restored ccvdeployment.EnvironmentTopology
		if err := toml.Unmarshal(topoSnap, &restored); err != nil {
			t.Logf("signer rotation test cleanup: restore topology: %v", err)
			return
		}
		*h.Cfg.EnvironmentTopology = restored
		h.Topology = ccv.BuildEnvironmentTopology(h.Cfg, h.Env)
		cleanupCtx := ccv.Plog.WithContext(context.Background())
		if err := ccv.ConfigureTopologyLanesAndOffchain(
			cleanupCtx, h.Env, h.Cfg, h.Topology, h.Selectors, h.Cfg.Blockchains, h.Impls, ccv.ReconfigureLanesParams{}, nil, environmentChangeReconcileOpts(),
		); err != nil {
			t.Logf("signer rotation test cleanup: reconcile: %v", err)
		}
	})
}

func evmDecimalChainIDsFromHarness(h *environmentChangeReconcileHarness) []string {
	var out []string
	for _, bc := range h.Cfg.Blockchains {
		if bc.Out == nil || bc.Out.Family != chain_selectors.FamilyEVM {
			continue
		}
		if bc.ChainID == "" {
			continue
		}
		out = append(out, bc.ChainID)
	}
	return out
}

func requireRotateNOPSigningKey(t *testing.T, ctx context.Context, h *environmentChangeReconcileHarness, nopAlias string) (addrOld, addrNew string) {
	t.Helper()
	require.NotNil(t, h.Cfg.ClientLookup)
	require.NotNil(t, h.Env.Offchain)
	require.NotEmpty(t, h.Env.NodeIDs)
	clClient, ok := h.Cfg.ClientLookup.GetClient(nopAlias)
	require.True(t, ok, "CL client for NOP %q", nopAlias)
	lookup, err := offchainshared.FetchNodeLookup(ctx, h.Env.Offchain, h.Env.NodeIDs)
	require.NoError(t, err)
	node, ok := lookup.FindByName(nopAlias)
	require.True(t, ok, "JD node for NOP %q", nopAlias)
	chainIDs := evmDecimalChainIDsFromHarness(h)
	require.NotEmpty(t, chainIDs)
	oldAddr, newAddr, err := jobs.RotateOCR2KeyBundle(ctx, clClient, h.Env.Offchain, node.Id, chainIDs)
	require.NoError(t, err)
	return oldAddr, newAddr
}

func updateNOPSignerAddressEVM(t *testing.T, topo *ccvdeployment.EnvironmentTopology, nopAlias, evmHex string) {
	t.Helper()
	require.NotNil(t, topo.NOPTopology)
	ok := topo.NOPTopology.SetNOPSignerAddress(nopAlias, chain_selectors.FamilyEVM, evmHex)
	require.True(t, ok, "NOP %q must exist in topology", nopAlias)
	require.NoError(t, topo.Validate())
}

func addRotationOverlapNOPToTopology(t *testing.T, topo *ccvdeployment.EnvironmentTopology, fakeAlias, evmAddrOld string) {
	t.Helper()
	require.NotNil(t, topo.NOPTopology)
	comm, ok := topo.NOPTopology.Committees[devenvcommon.DefaultCommitteeVerifierQualifier]
	require.True(t, ok, "default committee")
	fake := ccvdeployment.NOPConfig{
		Alias: fakeAlias,
		Name:  fakeAlias,
		SignerAddressByFamily: map[string]string{
			chain_selectors.FamilyEVM: evmAddrOld,
		},
		Mode: ccvshared.NOPModeStandalone,
	}
	topo.NOPTopology.NOPs = append(topo.NOPTopology.NOPs, fake)
	for sel, cc := range comm.ChainConfigs {
		next := slices.Clone(cc.NOPAliases)
		next = append(next, fakeAlias)
		cc.NOPAliases = next
		comm.ChainConfigs[sel] = cc
	}
	topo.NOPTopology.Committees[devenvcommon.DefaultCommitteeVerifierQualifier] = comm
	refreshNOPTopologyIndex(t, topo)
	require.NoError(t, topo.Validate())
}

func removeNOPFromTopology(t *testing.T, topo *ccvdeployment.EnvironmentTopology, alias string) {
	t.Helper()
	require.NotNil(t, topo.NOPTopology)
	topo.NOPTopology.NOPs = slices.DeleteFunc(slices.Clone(topo.NOPTopology.NOPs), func(n ccvdeployment.NOPConfig) bool {
		a := n.Alias
		if a == "" {
			a = n.Name
		}
		return a == alias
	})
	for qual, comm := range topo.NOPTopology.Committees {
		for sel, cc := range comm.ChainConfigs {
			if !slices.Contains(cc.NOPAliases, alias) {
				continue
			}
			next := slices.Clone(cc.NOPAliases)
			next = slices.DeleteFunc(next, func(a string) bool { return a == alias })
			require.NotEmpty(t, next, "committee %q chain %s would have no NOPs", qual, sel)
			cc.NOPAliases = next
			th := cc.Threshold
			if int(th) > len(cc.NOPAliases) {
				th = uint8(len(cc.NOPAliases))
			}
			if th < 1 {
				th = 1
			}
			cc.Threshold = th
			comm.ChainConfigs[sel] = cc
		}
		topo.NOPTopology.Committees[qual] = comm
	}
	refreshNOPTopologyIndex(t, topo)
	require.NoError(t, topo.Validate())
}

func changeThresholdInDefaultCommitteeChainConfigs(t *testing.T, topo *ccvdeployment.EnvironmentTopology, delta int) {
	t.Helper()
	require.NotNil(t, topo.NOPTopology)
	comm, ok := topo.NOPTopology.Committees[devenvcommon.DefaultCommitteeVerifierQualifier]
	require.True(t, ok, "default committee")
	for sel, cc := range comm.ChainConfigs {
		n := int(cc.Threshold) + delta
		require.GreaterOrEqual(t, n, 1, "threshold would drop below 1 on chain %s", sel)
		require.LessOrEqual(t, n, len(cc.NOPAliases), "threshold would exceed NOP count on chain %s", sel)
		cc.Threshold = uint8(n)
		comm.ChainConfigs[sel] = cc
	}
	topo.NOPTopology.Committees[devenvcommon.DefaultCommitteeVerifierQualifier] = comm
	require.NoError(t, topo.Validate())
}

func defaultCommitteeFirstChainThresholdAndSize(t *testing.T, topo *ccvdeployment.EnvironmentTopology) (threshold uint8, nopCount int) {
	t.Helper()
	require.NotNil(t, topo.NOPTopology)
	comm, ok := topo.NOPTopology.Committees[devenvcommon.DefaultCommitteeVerifierQualifier]
	require.True(t, ok, "default committee")
	for _, cc := range comm.ChainConfigs {
		return cc.Threshold, len(cc.NOPAliases)
	}
	require.Fail(t, "default committee has no chain configs")
	return 0, 0
}

func defaultCommitteeChainThresholdAndSize(t *testing.T, topo *ccvdeployment.EnvironmentTopology, chainSelector uint64) (threshold uint8, nopCount int) {
	t.Helper()
	require.NotNil(t, topo.NOPTopology)
	comm, ok := topo.NOPTopology.Committees[devenvcommon.DefaultCommitteeVerifierQualifier]
	require.True(t, ok, "default committee")
	cc, ok := comm.ChainConfigs[strconv.FormatUint(chainSelector, 10)]
	require.True(t, ok, "default committee chain config for selector %d", chainSelector)
	return cc.Threshold, len(cc.NOPAliases)
}

func requireEnvironmentChangeOnchainOnlyReconcile(t *testing.T, ctx context.Context, h *environmentChangeReconcileHarness, lane ccv.ReconfigureLanesParams) {
	t.Helper()
	require.NoError(t, ccv.ReconfigureLanesOnchainOnly(
		ctx, h.Env, h.Topology, h.Selectors, h.Cfg.Blockchains, h.Impls, lane,
	))
}

func requireEnvironmentChangeOffchainOnlyReconcile(t *testing.T, ctx context.Context, h *environmentChangeReconcileHarness) {
	t.Helper()
	require.NoError(t, ccv.ReconfigureOffchainOnly(
		ctx, h.Env, h.Cfg, h.Topology, h.Impls, environmentChangeReconcileOpts(),
	))
}

func indexerContainerName(t *testing.T, cfg *ccv.Cfg) string {
	t.Helper()
	require.GreaterOrEqual(t, len(cfg.Indexer), 1)
	require.NotNil(t, cfg.Indexer[0].Out)
	name := cfg.Indexer[0].Out.ContainerName
	if len(name) > 0 && name[0] == '/' {
		return name[1:]
	}
	return name
}

func refreshNOPTopologyIndex(t *testing.T, topo *ccvdeployment.EnvironmentTopology) {
	t.Helper()
	require.NotNil(t, topo.NOPTopology)
	raw, err := toml.Marshal(*topo.NOPTopology)
	require.NoError(t, err)
	var nt ccvdeployment.NOPTopology
	require.NoError(t, toml.Unmarshal(raw, &nt))
	topo.NOPTopology = &nt
}

func requireIndexerDiscoveryReplaySinceForce(t *testing.T, ctx context.Context, cfg *ccv.Cfg, since uint64) {
	t.Helper()
	containerName := indexerContainerName(t, cfg)
	out, err := execInContainer(ctx, containerName, replayCLIArgs(
		"discovery",
		"--since", strconv.FormatUint(since, 10),
		"--force",
	)...)
	require.NoError(t, err, "indexer discovery replay: %s", out)
}

func requireIndexerReplayMessagesByIDsForce(t *testing.T, ctx context.Context, cfg *ccv.Cfg, msgIDHex string) {
	t.Helper()
	containerName := indexerContainerName(t, cfg)
	out, err := execInContainer(ctx, containerName, replayCLIArgs("messages", "--ids", msgIDHex, "--force")...)
	require.NoError(t, err, "indexer messages replay: %s", out)
}

func requireIndexerMessagesDiscoveryMessagesReplayByIDsForce(t *testing.T, ctx context.Context, cfg *ccv.Cfg, discoverySince uint64, msgIDHex string) {
	t.Helper()
	requireIndexerReplayMessagesByIDsForce(t, ctx, cfg, msgIDHex)
	requireIndexerDiscoveryReplaySinceForce(t, ctx, cfg, discoverySince)
	requireIndexerReplayMessagesByIDsForce(t, ctx, cfg, msgIDHex)
}

func clNodeContainerAtGlobalSpecIndex(t *testing.T, cfg *ccv.Cfg, globalIdx int) string {
	t.Helper()
	g := 0
	for _, nsi := range cfg.NodeSets {
		require.NotNil(t, nsi, "nodeset input")
		require.NotNil(t, nsi.Out, "nodeset output required to resolve CL container")
		httpStart := nsi.HTTPPortRangeStart
		if httpStart == 0 {
			httpStart = nodesetpkg.DefaultHTTPPortStaticRangeStart
		}
		for li := range nsi.NodeSpecs {
			if g == globalIdx {
				wantPort := httpStart + li
				needle := ":" + strconv.Itoa(wantPort)
				for _, cl := range nsi.Out.CLNodes {
					require.NotNil(t, cl)
					require.NotNil(t, cl.Node)
					if strings.Contains(cl.Node.ExternalURL, needle) {
						return services.NormalizeDockerContainerName(cl.Node.ContainerName)
					}
				}
				require.Fail(t, fmt.Sprintf("no CL node found for expected HTTP port (port=%d nodeset=%q)", wantPort, nsi.Name))
			}
			g++
		}
	}
	require.Fail(t, fmt.Sprintf("global node spec index out of range: %d", globalIdx))
	return ""
}

func clNodeContainerForVerifier(t *testing.T, cfg *ccv.Cfg, nopAlias string) string {
	t.Helper()
	topo := cfg.EnvironmentTopology
	require.NotNil(t, topo)
	require.NotNil(t, topo.NOPTopology)
	idx, ok := topo.NOPTopology.GetNOPIndex(nopAlias)
	require.True(t, ok, "NOP alias %q not in topology", nopAlias)
	return clNodeContainerAtGlobalSpecIndex(t, cfg, idx)
}

func requireRestartDefaultExecutorContainers(t *testing.T, ctx context.Context, cfg *ccv.Cfg) {
	t.Helper()
	seen := make(map[string]struct{})
	var containerNames []string
	for _, exec := range cfg.Executor {
		if exec == nil || exec.ExecutorQualifier != devenvcommon.DefaultExecutorQualifier {
			continue
		}
		var containerName string
		if exec.Out != nil && exec.Out.ContainerName != "" {
			containerName = services.NormalizeDockerContainerName(exec.Out.ContainerName)
		} else if exec.NOPAlias != "" {
			containerName = clNodeContainerForVerifier(t, cfg, exec.NOPAlias)
		}
		require.NotEmpty(t, containerName, "default executor container name")
		if _, ok := seen[containerName]; ok {
			continue
		}
		seen[containerName] = struct{}{}
		containerNames = append(containerNames, containerName)
	}
	slices.Sort(containerNames)
	require.NotEmpty(t, containerNames, "default executor container names")
	for _, containerName := range containerNames {
		require.NoError(t, services.RestartContainer(ctx, containerName))
		require.NoError(t, waitCLNodeHealthy(ctx, containerName))
	}
}

func waitCLNodeHealthy(ctx context.Context, containerName string) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		_, err := execInContainer(ctx, containerName, "curl", "-sf", "http://localhost:6688/health")
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("CL node %s did not become healthy in time", containerName)
}

func rewindCLVerifierSourceHeights(t *testing.T, ctx context.Context, containerName string, verifierIDs []string, srcSel uint64) {
	t.Helper()
	require.NotEmpty(t, containerName)
	seen := make(map[string]struct{})
	var ids []string
	for _, id := range verifierIDs {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	require.NotEmpty(t, ids, "verifier IDs for CL rewind")
	_, err := execInContainer(ctx, containerName, "pkill", "-STOP", "-f", "chainlink")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = execInContainer(ctx, containerName, "pkill", "-CONT", "-f", "chainlink") })
	sel := strconv.FormatUint(srcSel, 10)
	for _, verifierID := range ids {
		_, err = execInContainer(ctx, containerName,
			"chainlink",
			"-c", "/config/config",
			"-c", "/config/overrides",
			"-c", "/config/user-overrides",
			"-s", "/config/secrets",
			"-s", "/config/secrets-overrides",
			"-s", "/config/user-secrets-overrides",
			"local", "ccv", "chain-statuses",
			"--password", "/config/node_password",
			"set-finalized-height",
			"--chain-selector", sel,
			"--verifier-id", verifierID,
			"--block-height", "0",
		)
		require.NoError(t, err)
	}
	require.NoError(t, services.RestartContainer(ctx, containerName))
	require.NoError(t, waitCLNodeHealthy(ctx, containerName))
}

func requireRewindAllDefaultVerifierSourceHeights(t *testing.T, ctx context.Context, cfg *ccv.Cfg, srcSel uint64) {
	t.Helper()
	type clRewind struct {
		containerName string
		verifierIDs   []string
	}
	clByNOP := make(map[string]*clRewind)
	rewound := 0
	for _, v := range cfg.Verifier {
		if v == nil || v.CommitteeName != devenvcommon.DefaultCommitteeVerifierQualifier {
			continue
		}
		if v.Out == nil || v.Out.VerifierID == "" {
			continue
		}
		switch v.Mode {
		case services.Standalone:
			if v.Out.ContainerName == "" {
				continue
			}
			containerName := services.NormalizeDockerContainerName(v.Out.ContainerName)
			vc := verifiercli.NewClient(containerName)
			require.NoError(t, vc.Pause(ctx))
			t.Cleanup(func() { vc.ResumeBestEffort(ctx) })
			_, err := vc.ChainStatuses().SetFinalizedHeight(ctx, verifiercli.FormatChainSelector(srcSel), v.Out.VerifierID, verifiercli.FormatBlockHeight(0))
			require.NoError(t, err)
			require.NoError(t, vc.RestartAndWaitReady(ctx))
			rewound++
		case services.CL:
			cr, ok := clByNOP[v.NOPAlias]
			if !ok {
				cr = &clRewind{containerName: clNodeContainerForVerifier(t, cfg, v.NOPAlias)}
				clByNOP[v.NOPAlias] = cr
			}
			cr.verifierIDs = append(cr.verifierIDs, v.Out.VerifierID)
			rewound++
		default:
			continue
		}
	}
	nopAliases := make([]string, 0, len(clByNOP))
	for a := range clByNOP {
		nopAliases = append(nopAliases, a)
	}
	slices.Sort(nopAliases)
	for _, a := range nopAliases {
		cr := clByNOP[a]
		rewindCLVerifierSourceHeights(t, ctx, cr.containerName, cr.verifierIDs, srcSel)
	}
	require.Greater(t, rewound, 0, "no default committee verifier with verifier_id and rewind target (standalone container or CL topology) found")
}

func TestEnvironmentChangeReconcile_SignerKeyRotationExpectMessagesSucceedEachPhase(t *testing.T) {
	h := newEnvironmentChangeReconcileHarness(t)
	snapshotEnvironmentTopologyCleanup(t, h)
	ctx := ccv.Plog.WithContext(environmentChangeLinkedLongContext(t))
	path := environmentChangeSmokeConfigPath()
	th, err := tcapi.NewTestHarness(ctx, path, h.Cfg, chain_selectors.FamilyEVM)
	if err != nil {
		t.Skipf("message verification needs tcapi harness: %v", err)
	}
	srcSel, destSel := twoDistinctEVMSelectorsFromHarness(t, h)
	src, dest := ccip17PairForSelectors(t, ctx, th.Lib, srcSel, destSel)

	oldNOP := pickRemovableNOPAliasFromDefaultCommittee(t, h.Topology)
	addrOld, addrNew := requireRotateNOPSigningKey(t, ctx, h, oldNOP)
	updateNOPSignerAddressEVM(t, h.Cfg.EnvironmentTopology, oldNOP, addrNew)
	require.NotEqualf(t, strings.ToLower(addrOld), strings.ToLower(addrNew), "rotation must change address")

	addRotationOverlapNOPToTopology(t, h.Cfg.EnvironmentTopology, rotationFakeNOPAlias, addrOld)
	h.Topology = ccv.BuildEnvironmentTopology(h.Cfg, h.Env)
	requireEnvironmentChangeReconcile(t, ctx, h, ccv.ReconfigureLanesParams{})
	requireEnvironmentChangeEOADefaultVerifierMessage(t, ctx, th, h.Cfg, src, dest)

	removeNOPFromTopology(t, h.Cfg.EnvironmentTopology, rotationFakeNOPAlias)
	h.Topology = ccv.BuildEnvironmentTopology(h.Cfg, h.Env)
	requireEnvironmentChangeReconcile(t, ctx, h, ccv.ReconfigureLanesParams{})

	ar, err := runEnvironmentChangeEOADefaultVerifierWithIndexedResult(ctx, th, h.Cfg, src, dest, false)
	if errors.Is(err, errEnvironmentChangeEOADefaultVerifierPrerequisites) {
		t.Skip("EOA default verifier prerequisites not met for this env")
	}
	require.NoError(t, err)
	requireVerifierResultsQuorumExcludesRecoveredSigner(t, ar, addrOld)
}

func TestEnvironmentChangeReconcile_SignerKeyRotationOffchainFirstExpectMessageSuccessAfterFullReconcile(t *testing.T) {
	h := newEnvironmentChangeReconcileHarness(t)
	snapshotEnvironmentTopologyCleanup(t, h)
	ctx := ccv.Plog.WithContext(environmentChangeLinkedLongContext(t))
	path := environmentChangeSmokeConfigPath()
	th, err := tcapi.NewTestHarness(ctx, path, h.Cfg, chain_selectors.FamilyEVM)
	if err != nil {
		t.Skipf("message verification needs tcapi harness: %v", err)
	}
	srcSel, destSel := twoDistinctEVMSelectorsFromHarness(t, h)
	src, dest := ccip17PairForSelectors(t, ctx, th.Lib, srcSel, destSel)

	T, N := defaultCommitteeChainThresholdAndSize(t, h.Topology, srcSel)
	if T == uint8(N) {
		t.Skipf("off-chain-first rotation needs T < N on source chain %d so remaining NOPs can meet threshold while one NOP is ignored", srcSel)
	}

	requireEnvironmentChangeReconcile(t, ctx, h, ccv.ReconfigureLanesParams{})

	oldNOP := pickRemovableNOPAliasFromDefaultCommittee(t, h.Topology)
	_ = requireNOPSigningKeyFromJD(t, h, oldNOP)
	addrOld, addrNew := requireRotateNOPSigningKey(t, ctx, h, oldNOP)
	updateNOPSignerAddressEVM(t, h.Cfg.EnvironmentTopology, oldNOP, addrNew)
	h.Topology = ccv.BuildEnvironmentTopology(h.Cfg, h.Env)

	requireEnvironmentChangeOffchainOnlyReconcile(t, ctx, h)
	requireEnvironmentChangeEOADefaultVerifierMessage(t, ctx, th, h.Cfg, src, dest)

	requireEnvironmentChangeReconcile(t, ctx, h, ccv.ReconfigureLanesParams{})
	ar, err := runEnvironmentChangeEOADefaultVerifierWithIndexedResult(ctx, th, h.Cfg, src, dest, false)
	if errors.Is(err, errEnvironmentChangeEOADefaultVerifierPrerequisites) {
		t.Skip("EOA default verifier prerequisites not met for this env")
	}
	require.NoError(t, err)
	requireVerifierResultsQuorumExcludesRecoveredSigner(t, ar, addrOld)
}

func TestEnvironmentChangeReconcile_ThresholdDecreaseExpectMessageSuccess(t *testing.T) {
	h := newEnvironmentChangeReconcileHarness(t)
	snapshotEnvironmentTopologyCleanup(t, h)
	ctx := ccv.Plog.WithContext(environmentChangeLinkedLongContext(t))
	path := environmentChangeSmokeConfigPath()
	th, err := tcapi.NewTestHarness(ctx, path, h.Cfg, chain_selectors.FamilyEVM)
	if err != nil {
		t.Skipf("message verification needs tcapi harness: %v", err)
	}
	srcSel, destSel := twoDistinctEVMSelectorsFromHarness(t, h)
	src, dest := ccip17PairForSelectors(t, ctx, th.Lib, srcSel, destSel)

	T, _ := defaultCommitteeFirstChainThresholdAndSize(t, h.Topology)
	if T < 2 {
		t.Skip("threshold decrease test needs initial threshold >= 2")
	}
	requireEnvironmentChangeReconcile(t, ctx, h, ccv.ReconfigureLanesParams{})
	requireEnvironmentChangeEOADefaultVerifierMessage(t, ctx, th, h.Cfg, src, dest)

	changeThresholdInDefaultCommitteeChainConfigs(t, h.Cfg.EnvironmentTopology, -1)
	h.Topology = ccv.BuildEnvironmentTopology(h.Cfg, h.Env)
	requireEnvironmentChangeReconcile(t, ctx, h, ccv.ReconfigureLanesParams{})
	requireEnvironmentChangeEOADefaultVerifierMessage(t, ctx, th, h.Cfg, src, dest)
}

func TestEnvironmentChangeReconcile_ThresholdIncreaseRecoveryExpectMessageSuccessAfterFullReconcile(t *testing.T) {
	h := newEnvironmentChangeReconcileHarness(t)
	snapshotEnvironmentTopologyCleanup(t, h)
	ctx := ccv.Plog.WithContext(environmentChangeLinkedLongContext(t))
	path := environmentChangeSmokeConfigPath()
	th, err := tcapi.NewTestHarness(ctx, path, h.Cfg, chain_selectors.FamilyEVM)
	if err != nil {
		t.Skipf("message verification needs tcapi harness: %v", err)
	}
	srcSel, destSel := twoDistinctEVMSelectorsFromHarness(t, h)
	src, dest := ccip17PairForSelectors(t, ctx, th.Lib, srcSel, destSel)

	T, N := defaultCommitteeFirstChainThresholdAndSize(t, h.Topology)
	if int(T) >= N {
		t.Skip("threshold increase test needs T < N")
	}

	requireEnvironmentChangeReconcile(t, ctx, h, ccv.ReconfigureLanesParams{})
	requireEnvironmentChangeEOADefaultVerifierMessage(t, ctx, th, h.Cfg, src, dest)

	changeThresholdInDefaultCommitteeChainConfigs(t, h.Cfg.EnvironmentTopology, +1)
	h.Topology = ccv.BuildEnvironmentTopology(h.Cfg, h.Env)
	requireEnvironmentChangeOnchainOnlyReconcile(t, ctx, h, ccv.ReconfigureLanesParams{})

	msgID, _, _, execState, err := runEnvironmentChangeEOADefaultVerifierIndexedResultUntilExecStops(ctx, th, h.Cfg, src, dest, false)
	if errors.Is(err, errEnvironmentChangeEOADefaultVerifierPrerequisites) {
		t.Skip("EOA default verifier prerequisites not met for this env")
	}
	require.NoError(t, err)
	require.Equal(t, cciptestinterfaces.ExecutionStateFailure, execState, "expected execution failure while on-chain threshold exceeds off-chain aggregation")

	requireEnvironmentChangeReconcile(t, ctx, h, ccv.ReconfigureLanesParams{})

	requireRewindAllDefaultVerifierSourceHeights(t, ctx, h.Cfg, srcSel)
	// Wait for the re-aggregation to complete
	time.Sleep(10 * time.Second)

	msgHex := "0x" + hex.EncodeToString(msgID[:])
	requireIndexerMessagesDiscoveryMessagesReplayByIDsForce(t, ctx, h.Cfg, 3, msgHex)
	requireRestartDefaultExecutorContainers(t, ctx, h.Cfg)
	t.Cleanup(func() {
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()+"-replay"))
	})

	requireEnvironmentChangeMessageReachesExecutionSuccess(t, ctx, dest, msgID)
}
