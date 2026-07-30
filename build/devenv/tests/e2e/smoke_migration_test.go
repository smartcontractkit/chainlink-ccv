package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials/insecure"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain/jd"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/migration"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi/basic"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// migrationMessageTimeout is generous on the post-cutover leg: the standalone services have just
// started, imported keys, and reconnected to JD.
const migrationMessageTimeout = 3 * time.Minute

// TestE2EMigration_CLToStandalone moves every node operator in the environment from CL mode to
// standalone and proves the lane still works either side of the cutover.
//
// The assertion that matters is not that messages flow, it is that they flow with the *same*
// identities. The committee's signer set and the executor's funded transmitter are untouched by
// this migration by design, so the test records both before the cutover and requires them to be
// unchanged after. If either moved, an operator following this procedure in production would need a
// committee signer-set update on every chain, or would have stranded their gas.
//
// Requires a migration profile: one committee, one aggregator, so each NOP runs a single verifier
// job and a single executor job. See env-cl-migration.toml.
func TestE2EMigration_CLToStandalone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	ctx := ccv.Plog.WithContext(t.Context())

	in, err := ccv.LoadOutput[ccv.Cfg](GetSmokeTestConfig())
	require.NoError(t, err)
	lib, err := ccv.NewLibFromCCVEnv(&ccv.Plog, GetSmokeTestConfig())
	require.NoError(t, err)

	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "migration test needs at least 2 chains")
	src, dst := chains[0].ChainSelector(), chains[1].ChainSelector()

	requireCLMode(t, in)

	jdClient := newJDClient(t, in)
	clientLookup := newCLNodeLookup(t, in)
	nops := migratingNOPs(t, in, clientLookup)

	// Everything JD holds for each NOP is read while the Chainlink node still owns its record: the
	// job specs to retarget, and the signing address the committee's signer set was built from.
	// After the cutover the record belongs to the standalone verifier, so neither can be read as it
	// was.
	//
	// The specs are retargeted rather than regenerated, so the migrated jobs carry exactly the
	// configuration the operator was already running, down to the externalJobID.
	stateBefore := fetchNOPJDState(t, ctx, jdClient, nops)
	signersBefore := signingAddresses(stateBefore)
	require.NotEmpty(t, signersBefore, "no CL-mode signing addresses found in JD")

	t.Log("sending a message before the cutover")
	sendAndConfirm(t, ctx, lib, src, dst)

	cutover := migration.Input{
		NOPs:              nops,
		Verifiers:         in.Verifier,
		Executors:         in.Executor,
		Aggregators:       in.Aggregator,
		BlockchainOutputs: blockchainOutputs(in),
		JDInfra: &jobs.JDInfrastructure{
			JDOutput:       in.JD.Out,
			OffchainClient: jdClient,
			NodeIDMap:      map[string]string{},
		},
		Topology: in.EnvironmentTopology,
		WorkDir:  t.TempDir(),
	}

	t.Log("running the cutover")
	result, err := migration.Run(ctx, cutover)
	require.NoError(t, err, "cutover failed")
	require.Len(t, result.NOPs, len(nops), "every NOP should have been migrated")

	t.Log("proposing standalone job specs")
	proposeStandaloneJobs(t, ctx, jdClient, in, result, stateBefore)

	t.Log("sending a message after the cutover")
	sendAndConfirm(t, ctx, lib, src, dst)

	// The point of the whole exercise.
	for alias, wantSigner := range signersBefore {
		got, ok := result.NOPs[alias]
		require.Truef(t, ok, "NOP %s was not migrated", alias)
		// Both sides are canonicalised before comparing. JD's copy and the cutover's copy of the same
		// key are formatted differently — the cutover reports an EIP-55 checksummed address, JD's is
		// lowercase — so comparing the strings as they arrive would fail on formatting alone.
		require.Equalf(t,
			ccvshared.CanonicalEVMAddress(wantSigner),
			ccvshared.CanonicalEVMAddress(got.SigningAddress),
			"NOP %s signing address changed from %s to %s; the committee signer set would need updating",
			alias, wantSigner, got.SigningAddress)
		require.NotEmptyf(t, got.TransmitterAddress, "NOP %s has no transmitter address", alias)
		require.NotEmptyf(t, got.VerifierJDNodeID, "NOP %s verifier did not adopt a JD record", alias)
		require.NotEmptyf(t, got.ExecutorJDNodeIDs, "NOP %s registered no standalone executor", alias)
	}

	// The topology must now describe what is actually running, or the next changeset run would
	// regenerate CL-mode job specs for processes that cannot read them.
	for _, nop := range in.EnvironmentTopology.NOPTopology.NOPs {
		require.Equalf(t, ccvshared.NOPModeStandalone, nop.GetMode(),
			"NOP %s was left in CL mode in the topology", nop.Alias)
	}
}

// signingAddresses projects each NOP's pre-cutover signing address out of what was read from JD.
func signingAddresses(state map[string]nopJDState) map[string]string {
	out := make(map[string]string, len(state))
	for alias, s := range state {
		out[alias] = s.SigningAddress
	}
	return out
}

func requireCLMode(t *testing.T, in *ccv.Cfg) {
	t.Helper()
	require.NotNil(t, in.EnvironmentTopology, "environment topology missing")
	require.NotNil(t, in.EnvironmentTopology.NOPTopology, "NOP topology missing")
	// Without this the per-NOP loops here and at the end of the test both pass on an empty topology,
	// and the migration is reported as working having migrated nothing.
	require.NotEmpty(t, in.EnvironmentTopology.NOPTopology.NOPs, "topology declares no NOPs")
	require.NotEmpty(t, in.NodeSets, "migration test requires CL nodes; use a migration.clnode profile")
	for _, nop := range in.EnvironmentTopology.NOPTopology.NOPs {
		require.Equalf(t, ccvshared.NOPModeCL, nop.GetMode(),
			"NOP %s is already standalone; the migration test must start from CL mode", nop.Alias)
	}
}

func newJDClient(t *testing.T, in *ccv.Cfg) offchain.Client {
	t.Helper()
	require.NotNil(t, in.JD, "JD input missing from environment output")
	require.NotNil(t, in.JD.Out, "JD output missing from environment output")
	client, err := jd.NewJDClient(jd.JDConfig{
		GRPC:  in.JD.Out.ExternalGRPCUrl,
		WSRPC: in.JD.Out.ExternalWSRPCUrl,
		Creds: insecure.NewCredentials(),
	})
	require.NoError(t, err)
	return client
}

func newCLNodeLookup(t *testing.T, in *ccv.Cfg) *jobs.NodeSetClientLookup {
	t.Helper()
	aliases := clModeAliases(in)
	lookup, err := jobs.NewNodeSetClientLookup(in.NodeSets, aliases)
	require.NoError(t, err)
	require.NotNil(t, lookup, "no CL node clients available")
	return lookup
}

func clModeAliases(in *ccv.Cfg) []string {
	var aliases []string
	for _, nop := range in.EnvironmentTopology.NOPTopology.NOPs {
		if nop.GetMode() == ccvshared.NOPModeCL {
			aliases = append(aliases, nop.Alias)
		}
	}
	return aliases
}

// clNodeContainerNames flattens the launched Chainlink node container names in node-set order,
// which is the same order NewNodeSetClientLookup pairs them with NOP aliases.
func clNodeContainerNames(t *testing.T, in *ccv.Cfg) []string {
	t.Helper()
	var names []string
	for _, nodeSet := range in.NodeSets {
		if nodeSet == nil {
			continue
		}
		for _, spec := range nodeSet.NodeSpecs {
			if spec == nil || spec.Out == nil || spec.Out.Node == nil {
				continue
			}
			require.NotEmpty(t, spec.Out.Node.ContainerName, "CL node output has no container name")
			names = append(names, spec.Out.Node.ContainerName)
		}
	}
	return names
}

// migratingNOPs builds the cutover input for every CL-mode NOP, pairing each with its Chainlink
// node client and the container to stop.
func migratingNOPs(t *testing.T, in *ccv.Cfg, lookup *jobs.NodeSetClientLookup) []migration.NOP {
	t.Helper()
	require.NotEmpty(t, in.Blockchains, "no blockchains in environment output")
	transmitterChainID := in.Blockchains[0].ChainID

	aliases := clModeAliases(in)
	containers := clNodeContainerNames(t, in)
	require.Lenf(t, containers, len(aliases),
		"expected one CL node container per CL-mode NOP, got %d containers for %d NOPs",
		len(containers), len(aliases))

	nops := make([]migration.NOP, 0, len(aliases))
	for i, alias := range aliases {
		client, ok := lookup.GetClient(alias)
		require.Truef(t, ok, "no CL client for NOP %s", alias)
		nops = append(nops, migration.NOP{
			Alias:              alias,
			CLClient:           client,
			CLContainerNames:   []string{containers[i]},
			TransmitterChainID: transmitterChainID,
		})
	}
	return nops
}

func blockchainOutputs(in *ccv.Cfg) []*blockchain.Output {
	outs := make([]*blockchain.Output, 0, len(in.Blockchains))
	for _, bc := range in.Blockchains {
		if bc != nil && bc.Out != nil {
			outs = append(outs, bc.Out)
		}
	}
	return outs
}

// nopJDState is what JD holds for a NOP while its Chainlink node still owns the record.
type nopJDState struct {
	Specs          []migration.NodeJobSpec
	SigningAddress string
}

// fetchNOPJDState reads each NOP's current job specs and signing address from JD, keyed by alias.
// Both come from the one node record, found by the node's own CSA key, so the signing address is
// the one belonging to the specs being carried across.
func fetchNOPJDState(
	t *testing.T,
	ctx context.Context,
	jdClient offchain.Client,
	nops []migration.NOP,
) map[string]nopJDState {
	t.Helper()
	out := make(map[string]nopJDState, len(nops))
	for _, nop := range nops {
		csaKey, err := jobs.CLCSAKeyProvider{Client: nop.CLClient}.CSAKey(ctx)
		require.NoErrorf(t, err, "reading CSA key for NOP %s", nop.Alias)
		node, err := migration.FindNodeByCSAKey(ctx, jdClient, csaKey)
		require.NoErrorf(t, err, "finding JD record for NOP %s", nop.Alias)

		specs, err := migration.FetchNodeJobSpecs(ctx, jdClient, node.GetId())
		require.NoErrorf(t, err, "fetching job specs for NOP %s", nop.Alias)
		require.NotEmptyf(t, specs, "NOP %s has no job specs in JD", nop.Alias)

		out[nop.Alias] = nopJDState{
			Specs:          specs,
			SigningAddress: jdSigningAddress(t, ctx, jdClient, nop.Alias, node.GetId()),
		}
	}
	return out
}

// jdSigningAddress reads the EVM signing address JD holds for a node.
//
// This is deliberately read from JD rather than from the topology's signer_address_by_family. That
// field is only ever written for standalone NOPs — enrichEnvironmentTopology skips CL-mode ones —
// so for the NOPs this test starts with it is always empty. JD is also where the verifier changeset
// itself reads the address it puts into the committee's signer set, which is the value the migration
// has to preserve.
func jdSigningAddress(t *testing.T, ctx context.Context, jdClient offchain.Client, alias, nodeID string) string {
	t.Helper()
	resp, err := jdClient.ListNodeChainConfigs(ctx, &nodev1.ListNodeChainConfigsRequest{
		Filter: &nodev1.ListNodeChainConfigsRequest_Filter{NodeIds: []string{nodeID}},
	})
	require.NoErrorf(t, err, "listing JD chain configs for NOP %s", alias)

	// One chain config per chain, each carrying the same OCR key bundle. Disagreement between them
	// would leave "the signing address before the cutover" undefined, so it fails rather than
	// picking one and asserting against it.
	signer := ""
	for _, chainConfig := range resp.GetChainConfigs() {
		addr, err := ccvshared.SigningIdentityFromBundle(chainsel.FamilyEVM, chainConfig.GetOcr2Config().GetOcrKeyBundle())
		if err != nil {
			continue
		}
		if signer == "" {
			signer = addr
			continue
		}
		require.Equalf(t, signer, addr, "NOP %s has conflicting EVM signing addresses in JD", alias)
	}
	require.NotEmptyf(t, signer, "JD holds no EVM signing address for NOP %s", alias)
	return signer
}

// proposeStandaloneJobs retargets each NOP's specs to the standalone envelope and routes them: the
// verifier job to the record the verifier adopted, the executor job to the record the executor
// registered. The CL node held both under one record; standalone splits them across two.
func proposeStandaloneJobs(
	t *testing.T,
	ctx context.Context,
	jdClient offchain.Client,
	in *ccv.Cfg,
	result migration.Result,
	stateByNOP map[string]nopJDState,
) {
	t.Helper()
	executorNodeByAlias := make(map[string]string)
	for _, exec := range in.Executor {
		if exec != nil && exec.Out != nil && exec.Out.JDNodeID != "" {
			executorNodeByAlias[exec.NOPAlias] = exec.Out.JDNodeID
		}
	}

	var proposals []migration.JobProposal
	for alias, state := range stateByNOP {
		nopResult, ok := result.NOPs[alias]
		require.Truef(t, ok, "no cutover result for NOP %s", alias)

		for _, spec := range state.Specs {
			retargeted, err := migration.RetargetJobSpec(spec.Spec)
			require.NoErrorf(t, err, "retargeting job %s for NOP %s", spec.JobID, alias)

			jobType, err := migration.JobSpecType(spec.Spec)
			require.NoErrorf(t, err, "reading type of job %s for NOP %s", spec.JobID, alias)

			nodeID := nopResult.VerifierJDNodeID
			if jobType == migration.JobTypeExecutor {
				nodeID, ok = executorNodeByAlias[alias]
				require.Truef(t, ok, "NOP %s has an executor job but no standalone executor record", alias)
			}
			proposals = append(proposals, migration.JobProposal{
				NodeID: nodeID,
				Spec:   retargeted,
				Label:  alias + "/" + spec.JobID,
			})
		}
	}

	require.NotEmpty(t, proposals, "no job specs to propose after the cutover")
	require.NoError(t, migration.ProposeJobs(ctx, jdClient, proposals))
}

func sendAndConfirm(t *testing.T, ctx context.Context, lib ccv.Lib, src, dst uint64) {
	t.Helper()
	tc := basic.EOAReceiverDefaultVerifier(lib, src, dst, basic.Args{
		Run: tcapi.RunConfig{
			ConfirmSentTimeout: migrationMessageTimeout,
			ConfirmExecTimeout: migrationMessageTimeout,
		},
	})
	require.True(t, tc.HavePrerequisites(ctx), "messaging prerequisites not met")
	_, err := tc.Run(ctx)
	require.NoError(t, err)
}
