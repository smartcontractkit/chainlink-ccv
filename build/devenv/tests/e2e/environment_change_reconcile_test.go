package e2e

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	routeroperations "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/proxy"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/versioned_verifier_resolver"
	ccipOffchain "github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/offchain"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/offchain/operations/fetch_signing_keys"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	ccvcomm "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/common/committee"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

func environmentChangeSmokeConfigPath() string {
	if p := os.Getenv("ENVIRONMENT_CHANGE_SMOKE_TEST_CONFIG"); p != "" {
		return p
	}
	return GetSmokeTestConfig()
}

func requireEnvironmentChangeEnvFile(t *testing.T) string {
	t.Helper()
	path := environmentChangeSmokeConfigPath()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("environment change E2E requires env-out (missing %q: %v); run ccv up and set ENVIRONMENT_CHANGE_SMOKE_TEST_CONFIG or use SMOKE_TEST_CONFIG via GetSmokeTestConfig", path, err)
	}
	return path
}

type environmentChangeReconcileHarness struct {
	Cfg       *ccv.Cfg
	Selectors []uint64
	Env       *deployment.Environment
	Topology  *ccipOffchain.EnvironmentTopology
	Impls     []cciptestinterfaces.CCIP17Configuration
}

const (
	environmentChangeAssertMessageTimeout   = 4 * time.Minute
	environmentChangePostMessageExecTimeout = 2 * time.Minute
)

var errEnvironmentChangeEOADefaultVerifierPrerequisites = errors.New("EOA default verifier message prerequisites not met")

func newEnvironmentChangeReconcileHarness(t *testing.T) *environmentChangeReconcileHarness {
	t.Helper()
	path := requireEnvironmentChangeEnvFile(t)
	cfg, err := ccv.LoadOutput[ccv.Cfg](path)
	require.NoError(t, err)
	if err := ccv.RequireFullCLModeForEnvironmentChangeReconcile(cfg); err != nil {
		t.Skipf("environment change reconcile E2E requires full CL mode (topology NOPs cl, verifier/executor mode cl, nodesets): %v; use a CL env-out or set ENVIRONMENT_CHANGE_SMOKE_TEST_CONFIG", err)
	}
	selectors, env, err := ccv.OpenDeploymentEnvironmentFromCfg(cfg)
	require.NoError(t, err)
	require.NotEmpty(t, selectors)
	topology := ccv.BuildEnvironmentTopology(cfg, env)
	require.NotNil(t, topology)
	impls, err := ccv.ImplConfigurationsFromCfg(cfg)
	require.NoError(t, err)
	require.Len(t, impls, len(cfg.Blockchains))
	return &environmentChangeReconcileHarness{
		Cfg:       cfg,
		Selectors: selectors,
		Env:       env,
		Topology:  topology,
		Impls:     impls,
	}
}

func testRouterDeployedOnSelector(t *testing.T, env *deployment.Environment, selector uint64) bool {
	t.Helper()
	_, err := env.DataStore.Addresses().Get(datastore.NewAddressRefKey(
		selector,
		datastore.ContractType(routeroperations.TestRouterContractType),
		semver.MustParse(routeroperations.DeployTestRouter.Version()),
		"",
	))
	return err == nil
}

func environmentChangeLinkedLongContext(t *testing.T) context.Context {
	t.Helper()
	base := t.Context()
	longCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	go func() {
		<-base.Done()
		cancel()
	}()
	t.Cleanup(cancel)
	return longCtx
}

func environmentChangeReconcileOpts() ccv.ConfigureOffchainOptions {
	return ccv.ConfigureOffchainOptions{FundExecutors: false}
}

func requireEnvironmentChangeReconcile(t *testing.T, ctx context.Context, h *environmentChangeReconcileHarness, lane ccv.ReconfigureLanesParams) {
	t.Helper()
	require.NoError(t, ccv.ConfigureTopologyLanesAndOffchain(
		ctx, h.Env, h.Cfg, h.Topology, h.Selectors, h.Cfg.Blockchains, h.Impls, lane, nil, environmentChangeReconcileOpts(),
	))
}

func requireNOPSigningKeyFromJD(t *testing.T, h *environmentChangeReconcileHarness, nopAlias string) string {
	t.Helper()
	require.NotNil(t, h.Env)
	require.NotNil(t, h.Env.Offchain)

	report, err := operations.ExecuteOperation(
		h.Env.OperationsBundle,
		fetch_signing_keys.FetchNOPSigningKeys,
		fetch_signing_keys.FetchSigningKeysDeps{
			JDClient: h.Env.Offchain,
			Logger:   h.Env.Logger,
			NodeIDs:  h.Env.NodeIDs,
		},
		fetch_signing_keys.FetchSigningKeysInput{NOPAliases: []string{nopAlias}},
	)
	require.NoError(t, err)

	signersByFamily, ok := report.Output.SigningKeysByNOP[nopAlias]
	require.True(t, ok, "NOP %q needs signing keys from JD", nopAlias)

	evmSigner := signersByFamily[chain_selectors.FamilyEVM]
	require.NotEmpty(t, evmSigner, "NOP %q needs EVM signer from JD", nopAlias)
	return evmSigner
}

type environmentChangeEOADefaultVerifierInputs struct {
	receiver protocol.UnknownAddress
	ccvs     []protocol.CCV
	executor protocol.UnknownAddress
}

func environmentChangeEOADefaultVerifierConfig(cfg *ccv.Cfg, src, dest cciptestinterfaces.CCIP17) (*environmentChangeEOADefaultVerifierInputs, error) {
	receiver, err := dest.GetEOAReceiverAddress()
	if err != nil {
		return nil, err
	}
	ccvAddr, err := tcapi.GetContractAddress(
		cfg,
		src.ChainSelector(),
		datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType),
		versioned_verifier_resolver.Version.String(),
		devenvcommon.DefaultCommitteeVerifierQualifier,
		"committee verifier proxy",
	)
	if err != nil {
		return nil, err
	}
	executorAddr, err := tcapi.GetContractAddress(
		cfg,
		src.ChainSelector(),
		datastore.ContractType(sequences.ExecutorProxyType),
		proxy.Deploy.Version(),
		devenvcommon.DefaultExecutorQualifier,
		"executor",
	)
	if err != nil {
		return nil, err
	}
	return &environmentChangeEOADefaultVerifierInputs{
		receiver: receiver,
		ccvs:     []protocol.CCV{{CCVAddress: ccvAddr, Args: []byte{}, ArgsLen: 0}},
		executor: executorAddr,
	}, nil
}

func runEnvironmentChangeEOADefaultVerifierWithIndexedResult(
	ctx context.Context,
	harness tcapi.TestHarness,
	cfg *ccv.Cfg,
	src, dest cciptestinterfaces.CCIP17,
	useTestRouter bool,
) (tcapi.AssertionResult, error) {
	inputs, err := environmentChangeEOADefaultVerifierConfig(cfg, src, dest)
	if err != nil {
		return tcapi.AssertionResult{}, fmt.Errorf("%w: %w", errEnvironmentChangeEOADefaultVerifierPrerequisites, err)
	}

	seqNo, err := src.GetExpectedNextSequenceNumber(ctx, dest.ChainSelector())
	if err != nil {
		return tcapi.AssertionResult{}, fmt.Errorf("failed to get expected next sequence number: %w", err)
	}
	sendMessageResult, err := src.SendMessage(
		ctx, dest.ChainSelector(), cciptestinterfaces.MessageFields{
			Receiver: inputs.receiver,
			Data:     []byte("multi-verifier test"),
		}, cciptestinterfaces.MessageOptions{
			Version:           3,
			ExecutionGasLimit: 200_000,
			FinalityConfig:    1,
			Executor:          inputs.executor,
			CCVs:              inputs.ccvs,
			UseTestRouter:     useTestRouter,
		},
	)
	if err != nil {
		return tcapi.AssertionResult{}, fmt.Errorf("failed to send message: %w", err)
	}
	if len(sendMessageResult.ReceiptIssuers) != 3 {
		return tcapi.AssertionResult{}, fmt.Errorf("expected 3 receipt issuers, got %d", len(sendMessageResult.ReceiptIssuers))
	}
	sentEvent, err := src.WaitOneSentEventBySeqNo(ctx, dest.ChainSelector(), seqNo, tcapi.DefaultSentTimeout)
	if err != nil {
		return tcapi.AssertionResult{}, fmt.Errorf("failed to wait for sent event: %w", err)
	}
	aggregatorClient := harness.AggregatorClients[devenvcommon.DefaultCommitteeVerifierQualifier]
	chainMap, err := harness.Lib.ChainsMap(ctx)
	if err != nil {
		return tcapi.AssertionResult{}, fmt.Errorf("failed to get chains map: %w", err)
	}
	testCtx, cleanup := tcapi.NewTestingContext(ctx, chainMap, aggregatorClient, harness.IndexerMonitor)
	defer cleanup()

	result, err := testCtx.AssertMessage(sentEvent.MessageID, tcapi.AssertMessageOptions{
		TickInterval:            time.Second,
		ExpectedVerifierResults: 1,
		Timeout:                 environmentChangeAssertMessageTimeout,
		AssertVerifierLogs:      false,
		AssertExecutorLogs:      false,
	})
	if err != nil {
		return result, fmt.Errorf("failed to assert message: %w", err)
	}
	if result.AggregatedResult == nil {
		return result, fmt.Errorf("aggregated result is nil")
	}
	if len(result.IndexedVerifications.Results) != 1 {
		return result, fmt.Errorf("expected 1 indexed verification, got %d", len(result.IndexedVerifications.Results))
	}
	e, err := chainMap[dest.ChainSelector()].WaitOneExecEventBySeqNo(ctx, src.ChainSelector(), seqNo, environmentChangePostMessageExecTimeout)
	if err != nil {
		return result, fmt.Errorf("failed to wait for exec event: %w", err)
	}
	if e.State != cciptestinterfaces.ExecutionStateSuccess {
		return result, fmt.Errorf("expected execution state success, got %s", e.State)
	}
	return result, nil
}

func twoDistinctEVMSelectorsFromHarness(t *testing.T, h *environmentChangeReconcileHarness) (srcSel, destSel uint64) {
	t.Helper()
	require.GreaterOrEqual(t, len(h.Cfg.Blockchains), 2, "need at least two chains")
	for _, bc := range h.Cfg.Blockchains {
		if bc.Out == nil || bc.Out.Family != chain_selectors.FamilyEVM {
			continue
		}
		d, err := chain_selectors.GetChainDetailsByChainIDAndFamily(bc.ChainID, bc.Out.Family)
		require.NoError(t, err)
		if srcSel == 0 {
			srcSel = d.ChainSelector
			continue
		}
		if d.ChainSelector != srcSel {
			destSel = d.ChainSelector
			break
		}
	}
	require.NotZero(t, destSel, "need two distinct EVM chain selectors")
	return srcSel, destSel
}

func reconfigureEnvironmentChangeCommitteeAllowlist(t *testing.T, h *environmentChangeReconcileHarness, srcSel uint64, args []committee_verifier.AllowlistConfigArgs) {
	t.Helper()
	ctx := ccv.Plog.WithContext(t.Context())
	patches := ccv.CommitteeRemotePatchesFromAllowlistArgs(srcSel, args)
	requireEnvironmentChangeReconcile(t, ctx, h, ccv.ReconfigureLanesParams{CommitteePatches: patches})
}

func reconfigureEnvironmentChangeAllowlistEnabled(t *testing.T, h *environmentChangeReconcileHarness, srcSel, destSel uint64, sender common.Address) {
	t.Helper()
	reconfigureEnvironmentChangeCommitteeAllowlist(t, h, srcSel, []committee_verifier.AllowlistConfigArgs{
		{
			DestChainSelector:       destSel,
			AllowlistEnabled:        true,
			AddedAllowlistedSenders: []common.Address{sender},
		},
	})
}

func reconfigureEnvironmentChangeAllowlistDisabled(t *testing.T, h *environmentChangeReconcileHarness, srcSel, destSel uint64, sender common.Address) {
	t.Helper()
	reconfigureEnvironmentChangeCommitteeAllowlist(t, h, srcSel, []committee_verifier.AllowlistConfigArgs{
		{
			DestChainSelector:         destSel,
			AllowlistEnabled:          false,
			RemovedAllowlistedSenders: []common.Address{sender},
		},
	})
}

func ccip17PairForSelectors(t *testing.T, ctx context.Context, lib *ccv.Lib, srcSel, destSel uint64) (src, dest cciptestinterfaces.CCIP17) {
	t.Helper()
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	for _, c := range chains {
		if c.Details.ChainSelector == srcSel {
			src = c.CCIP17
		}
		if c.Details.ChainSelector == destSel {
			dest = c.CCIP17
		}
	}
	require.NotNil(t, src, "no CCIP17 impl for source selector %d", srcSel)
	require.NotNil(t, dest, "no CCIP17 impl for dest selector %d", destSel)
	return src, dest
}

func requireEnvironmentChangeEOADefaultVerifierMessage(t *testing.T, ctx context.Context, th tcapi.TestHarness, cfg *ccv.Cfg, src, dest cciptestinterfaces.CCIP17) {
	t.Helper()
	_, err := runEnvironmentChangeEOADefaultVerifierWithIndexedResult(ctx, th, cfg, src, dest, false)
	if errors.Is(err, errEnvironmentChangeEOADefaultVerifierPrerequisites) {
		t.Skip("EOA default verifier message prerequisites not met for this env")
	}
	require.NoError(t, err)
}

func requireEnvironmentChangeEOADefaultVerifierMessageExpectError(t *testing.T, ctx context.Context, th tcapi.TestHarness, cfg *ccv.Cfg, src, dest cciptestinterfaces.CCIP17) {
	t.Helper()
	_, err := runEnvironmentChangeEOADefaultVerifierWithIndexedResult(ctx, th, cfg, src, dest, false)
	if errors.Is(err, errEnvironmentChangeEOADefaultVerifierPrerequisites) {
		t.Skip("EOA default verifier message prerequisites not met for this env")
	}
	require.Error(t, err, "EOA message must not complete end-to-end when committee allowlist excludes deployer")
}

func requireEnvironmentChangeEOADefaultVerifierMessageWithTestRouter(t *testing.T, ctx context.Context, th tcapi.TestHarness, cfg *ccv.Cfg, src, dest cciptestinterfaces.CCIP17, useTestRouter bool) {
	t.Helper()
	_, err := runEnvironmentChangeEOADefaultVerifierWithIndexedResult(ctx, th, cfg, src, dest, useTestRouter)
	if errors.Is(err, errEnvironmentChangeEOADefaultVerifierPrerequisites) {
		t.Skip("EOA default verifier message prerequisites not met for this env")
	}
	require.NoError(t, err)
}

func TestEnvironmentChangeReconcile_CommitteeVerifierAllowlistDecoyExpectErrorThenDeployerHappyPath(t *testing.T) {
	h := newEnvironmentChangeReconcileHarness(t)
	ctx := ccv.Plog.WithContext(t.Context())
	path := environmentChangeSmokeConfigPath()
	th, err := tcapi.NewTestHarness(ctx, path, h.Cfg, chain_selectors.FamilyEVM)
	if err != nil {
		t.Skipf("message verification needs tcapi harness (aggregators/indexer): %v", err)
	}
	srcSel, destSel := twoDistinctEVMSelectorsFromHarness(t, h)
	src, dest := ccip17PairForSelectors(t, ctx, th.Lib, srcSel, destSel)
	deployer := h.Env.BlockChains.EVMChains()[srcSel].DeployerKey.From
	decoy := common.HexToAddress("0x0000000000000000000000000000000000000001")
	require.NotEqual(t, deployer, decoy, "decoy allowlist entry must not be the chain deployer used to send messages")

	requireEnvironmentChangeEOADefaultVerifierMessage(t, ctx, th, h.Cfg, src, dest)

	reconfigureEnvironmentChangeAllowlistEnabled(t, h, srcSel, destSel, decoy)
	requireEnvironmentChangeEOADefaultVerifierMessageExpectError(t, ctx, th, h.Cfg, src, dest)

	reconfigureEnvironmentChangeAllowlistDisabled(t, h, srcSel, destSel, decoy)
	requireEnvironmentChangeEOADefaultVerifierMessage(t, ctx, th, h.Cfg, src, dest)

	reconfigureEnvironmentChangeAllowlistEnabled(t, h, srcSel, destSel, deployer)
	requireEnvironmentChangeEOADefaultVerifierMessage(t, ctx, th, h.Cfg, src, dest)

	reconfigureEnvironmentChangeAllowlistDisabled(t, h, srcSel, destSel, deployer)
	requireEnvironmentChangeEOADefaultVerifierMessage(t, ctx, th, h.Cfg, src, dest)
}

func testRouterSourceAndDestSelectors(t *testing.T, h *environmentChangeReconcileHarness) (srcSel, destSel uint64) {
	t.Helper()
	require.GreaterOrEqual(t, len(h.Selectors), 2, "need at least two chains for a directed lane")
	for _, sel := range h.Selectors {
		if !testRouterDeployedOnSelector(t, h.Env, sel) {
			continue
		}
		for _, other := range h.Selectors {
			if other != sel {
				return sel, other
			}
		}
	}
	return 0, 0
}

func TestEnvironmentChangeReconcile_TestRouterLaneThenProductionRouterExpectMessagesSucceedEachStage(t *testing.T) {
	h := newEnvironmentChangeReconcileHarness(t)
	ctx := ccv.Plog.WithContext(t.Context())
	srcSel, destSel := testRouterSourceAndDestSelectors(t, h)
	if srcSel == 0 {
		t.Skip("no chain in topology has TestRouter in datastore; redeploy with current devenv (TestRouter is deployed by default)")
	}
	path := environmentChangeSmokeConfigPath()
	th, err := tcapi.NewTestHarness(ctx, path, h.Cfg, chain_selectors.FamilyEVM)
	if err != nil {
		t.Skipf("message verification needs tcapi harness (aggregators/indexer): %v", err)
	}
	src, dest := ccip17PairForSelectors(t, ctx, th.Lib, srcSel, destSel)
	testRouterLanes := map[uint64]map[uint64]bool{
		srcSel: {destSel: true},
	}

	requireEnvironmentChangeEOADefaultVerifierMessageWithTestRouter(t, ctx, th, h.Cfg, src, dest, false)

	requireEnvironmentChangeReconcile(t, ctx, h, ccv.ReconfigureLanesParams{TestRouterByLane: testRouterLanes})
	requireEnvironmentChangeEOADefaultVerifierMessageWithTestRouter(t, ctx, th, h.Cfg, src, dest, true)

	requireEnvironmentChangeReconcile(t, ctx, h, ccv.ReconfigureLanesParams{})
	requireEnvironmentChangeEOADefaultVerifierMessageWithTestRouter(t, ctx, th, h.Cfg, src, dest, false)
}

func pickRemovableNOPAliasFromDefaultCommittee(t *testing.T, topo *ccipOffchain.EnvironmentTopology) string {
	t.Helper()
	require.NotNil(t, topo.NOPTopology)
	comm, ok := topo.NOPTopology.Committees[devenvcommon.DefaultCommitteeVerifierQualifier]
	require.True(t, ok, "default committee not in topology")
	var refAliases []string
	for sel, cc := range comm.ChainConfigs {
		require.GreaterOrEqual(t, len(cc.NOPAliases), 2, "chain %s needs at least 2 NOPs in default committee", sel)
		if refAliases == nil {
			refAliases = append([]string(nil), cc.NOPAliases...)
			continue
		}
		require.ElementsMatch(t, refAliases, cc.NOPAliases, "default committee NOP aliases must match across chains for this test")
	}
	return refAliases[len(refAliases)-1]
}

func removeNOPAliasFromEveryCommitteeChainConfigs(t *testing.T, topo *ccipOffchain.EnvironmentTopology, removeAlias string) {
	t.Helper()
	require.NotNil(t, topo.NOPTopology)
	for qual, comm := range topo.NOPTopology.Committees {
		for sel, cc := range comm.ChainConfigs {
			if !slices.Contains(cc.NOPAliases, removeAlias) {
				continue
			}
			next := slices.Clone(cc.NOPAliases)
			next = slices.DeleteFunc(next, func(a string) bool { return a == removeAlias })
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
	require.NoError(t, topo.Validate())
}

func requireVerifierResultsQuorumExcludesRecoveredSigner(t *testing.T, ar tcapi.AssertionResult, excludedSignerHex string) {
	t.Helper()
	excluded := common.HexToAddress(strings.TrimSpace(excludedSignerHex))
	require.NotEqual(t, common.Address{}, excluded, "excluded NOP signer must parse as an address")

	for i, row := range ar.IndexedVerifications.Results {
		vr := row.VerifierResult
		ccvData := vr.CCVData
		require.Greater(t, len(ccvData), committee.VerifierVersionLength, "indexed verification %d: ccv data too short", i)

		hash, err := committee.NewSignableHash(vr.MessageID, ccvData)
		require.NoError(t, err, "indexed verification %d: signable hash", i)

		rs, ss, err := protocol.DecodeSignatures(ccvData[committee.VerifierVersionLength:])
		require.NoError(t, err, "indexed verification %d: decode quorum signatures from ccv data", i)

		signers, err := protocol.RecoverECDSASigners(hash, rs, ss)
		require.NoError(t, err, "indexed verification %d: recover signers from quorum signatures", i)

		for _, sgn := range signers {
			require.NotEqualf(t, excluded, sgn,
				"indexed verification %d: recovered quorum signer must not be removed NOP %s (got %s)",
				i, excludedSignerHex, sgn.Hex())
		}
	}

	if ar.AggregatedResult != nil && len(ar.AggregatedResult.CcvData) > committee.VerifierVersionLength && ar.AggregatedResult.Message != nil {
		pm, err := ccvcomm.MapProtoMessageToProtocolMessage(ar.AggregatedResult.Message)
		require.NoError(t, err)
		mid, err := pm.MessageID()
		require.NoError(t, err)
		ccvData := ar.AggregatedResult.CcvData
		hash, err := committee.NewSignableHash(mid, ccvData)
		require.NoError(t, err)
		rs, ss, err := protocol.DecodeSignatures(ccvData[committee.VerifierVersionLength:])
		require.NoError(t, err)
		signers, err := protocol.RecoverECDSASigners(hash, rs, ss)
		require.NoError(t, err)
		for _, sgn := range signers {
			require.NotEqualf(t, excluded, sgn,
				"aggregated verifier result: recovered quorum signer must not be removed NOP %s (got %s)",
				excludedSignerHex, sgn.Hex())
		}
	}
}

func TestEnvironmentChangeReconcile_RemoveDefaultCommitteeNOPAndLowerThresholdExpectMessageSuccessWithoutRemovedNOPVerification(t *testing.T) {
	h := newEnvironmentChangeReconcileHarness(t)
	topoSnap, err := toml.Marshal(*h.Cfg.EnvironmentTopology)
	require.NoError(t, err)
	t.Cleanup(func() {
		var restored ccipOffchain.EnvironmentTopology
		if err := toml.Unmarshal(topoSnap, &restored); err != nil {
			t.Logf("reconcile test cleanup: restore topology: %v", err)
			return
		}
		*h.Cfg.EnvironmentTopology = restored
		h.Topology = ccv.BuildEnvironmentTopology(h.Cfg, h.Env)
		cleanupCtx := ccv.Plog.WithContext(context.Background())
		if err := ccv.ConfigureTopologyLanesAndOffchain(
			cleanupCtx, h.Env, h.Cfg, h.Topology, h.Selectors, h.Cfg.Blockchains, h.Impls, ccv.ReconfigureLanesParams{}, nil, environmentChangeReconcileOpts(),
		); err != nil {
			t.Logf("reconcile test cleanup: reconcile: %v", err)
		}
	})

	ctx := ccv.Plog.WithContext(environmentChangeLinkedLongContext(t))
	path := environmentChangeSmokeConfigPath()
	th, err := tcapi.NewTestHarness(ctx, path, h.Cfg, chain_selectors.FamilyEVM)
	if err != nil {
		t.Skipf("message verification needs tcapi harness (aggregators/indexer): %v", err)
	}
	srcSel, destSel := twoDistinctEVMSelectorsFromHarness(t, h)
	src, dest := ccip17PairForSelectors(t, ctx, th.Lib, srcSel, destSel)

	built := ccv.BuildEnvironmentTopology(h.Cfg, h.Env)
	removeAlias := pickRemovableNOPAliasFromDefaultCommittee(t, built)
	evmSigner := requireNOPSigningKeyFromJD(t, h, removeAlias)

	removeNOPAliasFromEveryCommitteeChainConfigs(t, h.Cfg.EnvironmentTopology, removeAlias)
	h.Topology = ccv.BuildEnvironmentTopology(h.Cfg, h.Env)

	requireEnvironmentChangeReconcile(t, ctx, h, ccv.ReconfigureLanesParams{})

	ar, err := runEnvironmentChangeEOADefaultVerifierWithIndexedResult(ctx, th, h.Cfg, src, dest, false)
	if errors.Is(err, errEnvironmentChangeEOADefaultVerifierPrerequisites) {
		t.Skip("EOA default verifier prerequisites not met for this env")
	}
	require.NoError(t, err)
	requireVerifierResultsQuorumExcludesRecoveredSigner(t, ar, evmSigner)
}
