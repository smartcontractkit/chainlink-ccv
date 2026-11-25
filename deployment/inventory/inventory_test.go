package inventory

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

const (
	ethereum = ChainSelector(5009297550715157269)  // ethereum-mainnet
	base     = ChainSelector(15971525489660198786) // ethereum-mainnet-base-1
	canton   = ChainSelector(2308837218439511688)  // canton-mainnet
)

// Synthetic signers: each canton key is the uncompressed form of the same NOP's evm address,
// except the shared placeholder and the 66-byte key, which exercise identity error handling.
const (
	alphaAddr      = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
	alphaKey       = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
	betaAddr       = "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf"
	betaKey        = "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
	gammaAddr      = "0x6813eb9362372eef6200f3b1dbc3f819671cba69"
	standaloneAddr = "0x1eff47bc3a10a45d4b230b5d10e37751fe6aa718"
	standaloneKey  = "04e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd1351ed993ea0d455b75642e2098ea51448d967ae33bfbdfe40cfe97bdc47739922"
	sharedAAddr    = "0xe57bfe9f44b819898f47bf37e5af72a0783e1141"
	placeholderKey = "042f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6"
	placeholderAdr = "0xe1ab8145f7e55dc933d51a18c793f901a3a0b276"
	invalidNOPAddr = "0xd41c057fd1c78805aac12b0a94a405c0461a6fbb"
	invalidNOPKey  = "045cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da00"
	unknownAddr    = "0x00000000000000000000000000000000000000aa"
)

func TestCanonicalSigner(t *testing.T) {
	t.Parallel()

	assert.Equal(t, alphaAddr, canonicalSigner("evm", "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"))
	assert.Equal(t, alphaAddr, canonicalSigner("canton", alphaKey))
	assert.Equal(t, alphaAddr, canonicalSigner("canton", "0x"+alphaKey))
	assert.Empty(t, canonicalSigner("canton", invalidNOPKey))
	assert.Empty(t, canonicalSigner("evm", "not-hex"))
}

func TestBuild_ResolvesCommitteesNodesAndPools(t *testing.T) {
	t.Parallel()

	inv := Build(fixtureInputs())
	assert.Equal(t, SchemaVersion, inv.SchemaVersion)

	eth := committeeFor(t, inv, SourceAggregator, ethereum)
	assert.Equal(t, []string{"aggregator-1", "aggregator-2"}, eth.Aggregators, "identical sets merge across aggregators")
	assert.Equal(t, "default", eth.Qualifier)
	assert.Equal(t, uint8(2), eth.Threshold)
	assert.Equal(t, Member{SignerAddress: alphaAddr, SignerPubKey: alphaKey, NOPAlias: "nop-alpha", NodeID: "node_alpha", CSAKey: "csa-alpha"},
		memberFor(t, eth, alphaAddr))
	assert.Equal(t, "node_gamma", memberFor(t, eth, gammaAddr).NodeID, "gamma signs from its verifier node, not its executor node")

	cantonSet := committeeFor(t, inv, SourceAggregator, canton)
	standalone := memberFor(t, cantonSet, standaloneAddr)
	assert.Equal(t, "nop-standalone", standalone.NOPAlias)
	assert.Equal(t, "node_standalone", standalone.NodeID, "a node with no recorded jobs signs when it is named after the alias")
	assert.Equal(t, standaloneKey, standalone.SignerPubKey)

	assert.Equal(t, []Role{RoleVerifier}, nodeFor(t, inv, "node_standalone").Roles, "committee membership marks the node as a verifier")
	assert.Equal(t, []Role{RoleExecutor, RoleVerifier}, nodeFor(t, inv, "node_alpha").Roles)
	assert.Equal(t, []Role{RoleExecutor}, nodeFor(t, inv, "node_gamma_exec").Roles)
	assert.Equal(t, "nop-gamma", nodeFor(t, inv, "node_gamma_exec").NOPAlias, "a job pins its node to the NOP")
	assert.Equal(t, []string{"node_gamma", "node_gamma_exec"}, nopFor(t, inv, "nop-gamma").NodeIDs)

	both := []string{"aggregator-1", "aggregator-2"}
	assert.Equal(t, []Verifier{
		{Chain: canton, Qualifier: "default", Address: "canton-verifier", Aggregators: both},
		{Chain: ethereum, Qualifier: "default", Address: "0x1000000000000000000000000000000000000002", Aggregators: both},
	}, inv.Verifiers)

	ethPool := executorPoolFor(t, inv, "default", ethereum)
	assert.Equal(t, []ExecutorMember{
		{NOPAlias: "nop-alpha", NodeID: "node_alpha", CSAKey: "csa-alpha", Mode: "cl"},
		{NOPAlias: "nop-beta", NodeID: "node_beta", CSAKey: "csa-beta", Mode: "cl"},
		{NOPAlias: "nop-gamma", NodeID: "node_gamma_exec", CSAKey: "csa-gamma-exec", Mode: "standalone"},
	}, ethPool.Members)
	assert.True(t, executorPoolFor(t, inv, "default", canton).Members[0].Unsupported, "CL nodes do not execute Canton")

	assert.Equal(t, []Chain{
		{Selector: canton, Name: "canton-mainnet", Family: "canton"},
		{Selector: ethereum, Name: "ethereum-mainnet", Family: "evm"},
		{Selector: base, Name: "ethereum-mainnet-base-1", Family: "evm"},
	}, inv.Chains)

	assert.Equal(t, []Issue{
		{Kind: IssueAmbiguousSigner, Subject: placeholderAdr, Detail: "claimed by nop-shared-a, nop-shared-b"},
		{
			Kind: IssueInvalidSigner, Subject: "nop-invalid",
			Detail: fmt.Sprintf("canton signer %q is neither a 20-byte address nor a 65-byte secp256k1 key", invalidNOPKey),
		},
		{Kind: IssueSignerMismatch, Subject: "nop-shared-a", Detail: "signers reduce to different addresses: " + placeholderAdr + ", " + sharedAAddr},
		{Kind: IssueUnresolvedSigner, Subject: unknownAddr, Detail: "no NOP signer matches it; used for ethereum-mainnet-base-1"},
		{
			Kind: IssueUnsupportedExecutorChain, Subject: "canton-mainnet",
			Detail: "pool default configures 1 CL-mode NOPs here, but CL nodes only run EVM chain blocks: nop-alpha",
		},
	}, inv.Issues)
}

func TestBuild_ExecutorPoolsUsePoolSpecificNodes(t *testing.T) {
	t.Parallel()

	jobs := shared.NOPJobs{"nop": {}}
	for _, pool := range []string{"default", "secondary"} {
		jobID := "nop-" + pool + "-executor"
		jobs["nop"][shared.JobID(jobID)] = shared.JobInfo{
			JobID: shared.JobID(jobID), NOPAlias: "nop", NodeID: "node-" + pool, Mode: shared.NOPModeStandalone,
			Spec: executorSpec("appConfig", map[ChainSelector][]string{ethereum: {"nop"}}),
		}
	}
	inv := Build(Inputs{
		Nodes: map[string]NodeRecord{
			"node-default":   {Name: "executor-default", CSAKey: "csa-default"},
			"node-secondary": {Name: "executor-secondary", CSAKey: "csa-secondary"},
		},
		Jobs: jobs,
	})

	assert.Equal(t, ExecutorMember{NOPAlias: "nop", NodeID: "node-default", CSAKey: "csa-default", Mode: "standalone"},
		executorPoolFor(t, inv, "default", ethereum).Members[0])
	assert.Equal(t, ExecutorMember{NOPAlias: "nop", NodeID: "node-secondary", CSAKey: "csa-secondary", Mode: "standalone"},
		executorPoolFor(t, inv, "secondary", ethereum).Members[0])
}

func TestBuild_AggregatorDriftIsPerCommittee(t *testing.T) {
	t.Parallel()

	sameCommittee := Build(Inputs{
		Aggregators:          map[string]*model.Committee{"aggregator-1": aggregatorConfig(2), "aggregator-2": aggregatorConfig(3)},
		AggregatorQualifiers: map[string]string{"aggregator-1": "default", "aggregator-2": "default"},
	})
	assert.Len(t, committeesFor(sameCommittee, ethereum), 2)
	assert.Contains(t, sameCommittee.Issues, Issue{
		Kind: IssueAggregatorDrift, Subject: "ethereum-mainnet (default)", Detail: "aggregators hold 2 different signer sets for this source",
	})

	twoCommittees := Build(Inputs{
		Aggregators:          map[string]*model.Committee{"aggregator-1": aggregatorConfig(2), "aggregator-2": aggregatorConfig(3)},
		AggregatorQualifiers: map[string]string{"aggregator-1": "default", "aggregator-2": "secondary"},
	})
	sets := committeesFor(twoCommittees, ethereum)
	require.Len(t, sets, 2)
	assert.Equal(t, []string{"default", "secondary"}, []string{sets[0].Qualifier, sets[1].Qualifier})
	for _, issue := range twoCommittees.Issues {
		assert.NotEqual(t, IssueAggregatorDrift, issue.Kind, "different committees may hold different sets")
	}
}

func TestBuild_CommitteeScopedVerifierNodes(t *testing.T) {
	t.Parallel()

	inv := Build(twoVerifierNodeInputs("nop-default-verifier", "nop-secondary-verifier", map[string]string{
		"aggregator-1": "default", "aggregator-2": "secondary",
	}))
	sets := committeesFor(inv, ethereum)
	require.Len(t, sets, 2, "the same signer set under two qualifiers is two committees")
	for _, c := range sets {
		m := memberFor(t, c, alphaAddr)
		assert.Equal(t, "node-"+c.Qualifier, m.NodeID, "committee %s resolves its own scoped node", c.Qualifier)
		assert.Equal(t, "csa-"+c.Qualifier, m.CSAKey)
	}
}

func TestBuild_AmbiguousVerifierNodeIsNotGuessed(t *testing.T) {
	t.Parallel()

	t.Run("two nodes scoped to the same committee", func(t *testing.T) {
		inv := Build(twoVerifierNodeInputs("nop-default-verifier", "nop-aggregator-1-default-verifier", map[string]string{
			"aggregator-1": "default", "aggregator-2": "default",
		}))
		assertAmbiguousMember(t, inv)
	})

	t.Run("no node scoped to the committee", func(t *testing.T) {
		inv := Build(twoVerifierNodeInputs("nop-alpha-verifier", "nop-beta-verifier", map[string]string{
			"aggregator-1": "default", "aggregator-2": "default",
		}))
		assertAmbiguousMember(t, inv)
	})
}

// twoVerifierNodeInputs builds one NOP running two verifier jobs (jobA on node-default,
// jobB on node-secondary) and one ethereum committee per aggregator qualifier.
func twoVerifierNodeInputs(jobA, jobB string, qualifiers map[string]string) Inputs {
	jobs := shared.NOPJobs{"nop": {}}
	for jobID, nodeID := range map[string]string{jobA: "node-default", jobB: "node-secondary"} {
		jobs["nop"][shared.JobID(jobID)] = shared.JobInfo{
			JobID: shared.JobID(jobID), NOPAlias: "nop", NodeID: nodeID, Spec: verifierSpec(),
		}
	}
	aggregators := make(map[string]*model.Committee, len(qualifiers))
	for name := range qualifiers {
		aggregators[name] = &model.Committee{QuorumConfigs: map[model.SourceSelector]*model.QuorumConfig{
			fmt.Sprint(ethereum): {Signers: []model.Signer{{Address: alphaAddr}}, Threshold: 1},
		}}
	}
	return Inputs{
		Aggregators:          aggregators,
		AggregatorQualifiers: qualifiers,
		Signers:              map[string]map[string]string{"nop": {"evm": alphaAddr}},
		Nodes: map[string]NodeRecord{
			"node-default":   {Name: "verifier-default", CSAKey: "csa-default"},
			"node-secondary": {Name: "verifier-secondary", CSAKey: "csa-secondary"},
		},
		Jobs: jobs,
	}
}

func assertAmbiguousMember(t *testing.T, inv *Inventory) {
	t.Helper()
	m := memberFor(t, committeeFor(t, inv, SourceAggregator, ethereum), alphaAddr)
	assert.Equal(t, "nop", m.NOPAlias)
	assert.Empty(t, m.NodeID, "an ambiguous signer keeps no node rather than a guessed one")
	assert.Empty(t, m.CSAKey)
	assert.Contains(t, inv.Issues, Issue{
		Kind: IssueAmbiguousNode, Subject: "nop",
		Detail: `several verifier nodes could sign for committee "default"; node left unresolved`,
	})
}

func TestBuild_ScopeConflictLeavesNodeUnresolved(t *testing.T) {
	t.Parallel()

	// The NOP's only verifier node is scoped to default (a known qualifier); one committee
	// is secondary, which that node does not cover.
	quorum := func() *model.Committee {
		return &model.Committee{QuorumConfigs: map[model.SourceSelector]*model.QuorumConfig{
			fmt.Sprint(ethereum): {Signers: []model.Signer{{Address: alphaAddr}}, Threshold: 1},
		}}
	}
	in := Inputs{
		Aggregators:          map[string]*model.Committee{"aggregator-1": quorum(), "aggregator-2": quorum()},
		AggregatorQualifiers: map[string]string{"aggregator-1": "secondary", "aggregator-2": "default"},
		Signers:              map[string]map[string]string{"nop": {"evm": alphaAddr}},
		Nodes:                map[string]NodeRecord{"node-default": {Name: "verifier-default", CSAKey: "csa-default"}},
		Jobs: shared.NOPJobs{"nop": {
			"nop-default-verifier": {JobID: "nop-default-verifier", NOPAlias: "nop", NodeID: "node-default", Spec: verifierSpec()},
		}},
	}
	inv := Build(in)
	sets := committeesFor(inv, ethereum)
	require.Len(t, sets, 2)
	for _, c := range sets {
		m := memberFor(t, c, alphaAddr)
		assert.Equal(t, "nop", m.NOPAlias)
		if c.Qualifier == "default" {
			assert.Equal(t, "node-default", m.NodeID, "the matching committee resolves the node")
			assert.Equal(t, "csa-default", m.CSAKey)
		} else {
			assert.Empty(t, m.NodeID, "a node scoped to another committee is never assigned by fallback")
			assert.Empty(t, m.CSAKey)
		}
	}
	assert.Contains(t, inv.Issues, Issue{
		Kind: IssueVerifierScopeConflict, Subject: "nop",
		Detail: `recorded verifier scope does not cover committee "secondary", source ethereum-mainnet; node left unresolved`,
	})
}

func TestBuild_SourceChainScopesResolution(t *testing.T) {
	t.Parallel()

	// Two verifier jobs in the default committee, each covering a different source chain.
	jobs := shared.NOPJobs{"nop": {
		"nop-default-verifier": {
			JobID: "nop-default-verifier", NOPAlias: "nop", NodeID: "node-eth",
			Spec: verifierSpecWithChains(uint64(ethereum)),
		},
		"nop-aggregator-1-default-verifier": {
			JobID: "nop-aggregator-1-default-verifier", NOPAlias: "nop", NodeID: "node-base",
			Spec: verifierSpecWithChains(uint64(base)),
		},
	}}
	in := Inputs{
		Aggregators: map[string]*model.Committee{"aggregator-1": {QuorumConfigs: map[model.SourceSelector]*model.QuorumConfig{
			fmt.Sprint(ethereum): {Signers: []model.Signer{{Address: alphaAddr}}, Threshold: 1},
			fmt.Sprint(base):     {Signers: []model.Signer{{Address: alphaAddr}}, Threshold: 1},
			fmt.Sprint(canton):   {Signers: []model.Signer{{Address: alphaAddr}}, Threshold: 1},
		}}},
		AggregatorQualifiers: map[string]string{"aggregator-1": "default"},
		Signers:              map[string]map[string]string{"nop": {"evm": alphaAddr}},
		Nodes: map[string]NodeRecord{
			"node-eth":  {Name: "verifier-eth", CSAKey: "csa-eth"},
			"node-base": {Name: "verifier-base", CSAKey: "csa-base"},
		},
		Jobs: jobs,
	}
	inv := Build(in)

	eth := memberFor(t, committeeFor(t, inv, SourceAggregator, ethereum), alphaAddr)
	assert.Equal(t, "node-eth", eth.NodeID)
	assert.Equal(t, "csa-eth", eth.CSAKey)
	baseMember := memberFor(t, committeeFor(t, inv, SourceAggregator, base), alphaAddr)
	assert.Equal(t, "node-base", baseMember.NodeID)
	assert.Equal(t, "csa-base", baseMember.CSAKey)

	cantonMember := memberFor(t, committeeFor(t, inv, SourceAggregator, canton), alphaAddr)
	assert.Empty(t, cantonMember.NodeID, "no recorded job covers canton, so no node is guessed")
	assert.Contains(t, inv.Issues, Issue{
		Kind: IssueVerifierScopeConflict, Subject: "nop",
		Detail: `recorded verifier scope does not cover committee "default", source canton-mainnet; node left unresolved`,
	})
}

// verifierSpecWithChains renders a ccvcommitteeverifier spec whose config covers the given
// source chains through its committee verifier address map.
func verifierSpecWithChains(chains ...uint64) string {
	entries := make([]string, 0, len(chains))
	for _, chain := range chains {
		entries = append(entries, fmt.Sprintf(`"%d" = "0x1000000000000000000000000000000000000002"`, chain))
	}
	return fmt.Sprintf("schemaVersion = 1\ntype = \"ccvcommitteeverifier\"\ncommitteeVerifierConfig = '''\ncommittee_verifier_addresses = {%s}\n'''\n",
		strings.Join(entries, ", "))
}

func TestBuild_EmptyInputs(t *testing.T) {
	t.Parallel()

	assert.True(t, Inputs{}.Empty())
	inv := Build(Inputs{})
	assert.Empty(t, inv.NOPs)
	assert.Empty(t, inv.Committees)
	assert.Empty(t, inv.Issues)
}

func TestViews(t *testing.T) {
	t.Parallel()

	inv := Build(fixtureInputs())

	alpha := inv.ByNOP()["nop-alpha"]
	assert.Equal(t, []ChainSelector{ethereum}, alpha.VerifierFor)
	assert.Equal(t, []ChainSelector{ethereum}, alpha.ExecutorOn, "unsupported memberships are not execution")
	require.Len(t, alpha.Nodes, 1)
	assert.Equal(t, "csa-alpha", alpha.Nodes[0].CSAKey)

	cantonView := inv.ByChain()[canton]
	require.Len(t, cantonView.Committees, 1)
	assert.Equal(t, standaloneAddr, cantonView.Committees[0].Members[0].SignerAddress)
	require.Len(t, cantonView.Verifiers, 1)
	require.Len(t, cantonView.ExecutorPools, 1)

	rows := inv.Rows()
	assert.Len(t, rows, 9, "5 committee members and 4 executor pool members")

	var buf bytes.Buffer
	require.NoError(t, WriteCSV(&buf, rows))
	records, err := csv.NewReader(&buf).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 10)
	assert.Equal(t, csvHeader, records[0])
	i := slices.IndexFunc(records, func(r []string) bool { return r[9] == "nop-standalone" })
	require.GreaterOrEqual(t, i, 0)
	assert.Equal(t, []string{
		"verifier", "aggregator", "default", "aggregator-1,aggregator-2", "2308837218439511688", "canton-mainnet", "canton", "",
		"1", "nop-standalone", "node_standalone", "nop-standalone", "csa-standalone", standaloneAddr, standaloneKey, "false",
	}, records[i])
}

// fixtureInputs is what CCV changesets would have persisted for a synthetic multi-chain environment.
func fixtureInputs() Inputs {
	pools := map[ChainSelector][]string{ethereum: {"nop-alpha", "nop-beta", "nop-gamma"}, canton: {"nop-alpha"}}
	jobs := []shared.JobInfo{
		{JobID: "nop-alpha-default-verifier", NOPAlias: "nop-alpha", NodeID: "node_alpha", Mode: shared.NOPModeCL, Spec: verifierSpec()},
		{JobID: "nop-alpha-default-executor", NOPAlias: "nop-alpha", NodeID: "node_alpha", Mode: shared.NOPModeCL, Spec: executorSpec("executorConfig", pools)},
		{JobID: "nop-beta-default-verifier", NOPAlias: "nop-beta", NodeID: "node_beta", Mode: shared.NOPModeCL, Spec: verifierSpec()},
		{JobID: "nop-beta-default-executor", NOPAlias: "nop-beta", NodeID: "node_beta", Mode: shared.NOPModeCL, Spec: executorSpec("executorConfig", pools)},
		{JobID: "nop-gamma-default-verifier", NOPAlias: "nop-gamma", NodeID: "node_gamma", Mode: shared.NOPModeStandalone, Spec: verifierSpec()},
		{JobID: "nop-gamma-default-executor", NOPAlias: "nop-gamma", NodeID: "node_gamma_exec", Mode: shared.NOPModeStandalone, Spec: executorSpec("appConfig", pools)},
	}
	nopJobs := make(shared.NOPJobs)
	for _, job := range jobs {
		if nopJobs[job.NOPAlias] == nil {
			nopJobs[job.NOPAlias] = make(map[shared.JobID]shared.JobInfo)
		}
		nopJobs[job.NOPAlias][job.JobID] = job
	}

	return Inputs{
		Aggregators:          map[string]*model.Committee{"aggregator-1": aggregatorConfig(2), "aggregator-2": aggregatorConfig(2)},
		AggregatorQualifiers: map[string]string{"aggregator-1": "default", "aggregator-2": "default"},
		Signers: map[string]map[string]string{
			"nop-alpha":      {"evm": alphaAddr, "canton": alphaKey},
			"nop-beta":       {"evm": betaAddr, "canton": betaKey},
			"nop-gamma":      {"evm": gammaAddr},
			"nop-standalone": {"evm": standaloneAddr, "canton": standaloneKey},
			"nop-shared-a":   {"evm": sharedAAddr, "canton": placeholderKey},
			"nop-shared-b":   {"canton": placeholderKey},
			"nop-invalid":    {"evm": invalidNOPAddr, "canton": invalidNOPKey},
		},
		Nodes: map[string]NodeRecord{
			"node_alpha":      {Name: "nop-alpha", CSAKey: "csa-alpha", Labels: map[string]string{"product": "ccv"}},
			"node_beta":       {Name: "nop-beta", CSAKey: "csa-beta"},
			"node_gamma":      {Name: "nop-gamma", CSAKey: "csa-gamma"},
			"node_gamma_exec": {Name: "chainlink-evm-executor-gamma", CSAKey: "csa-gamma-exec"},
			"node_standalone": {Name: "nop-standalone", CSAKey: "csa-standalone"},
		},
		Jobs: nopJobs,
	}
}

func aggregatorConfig(ethThreshold uint8) *model.Committee {
	return &model.Committee{
		QuorumConfigs: map[model.SourceSelector]*model.QuorumConfig{
			fmt.Sprint(ethereum): {
				SourceVerifierAddress: "0x1000000000000000000000000000000000000001",
				Signers:               []model.Signer{{Address: "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"}, {Address: betaAddr}, {Address: gammaAddr}},
				Threshold:             ethThreshold,
			},
			fmt.Sprint(canton): {Signers: []model.Signer{{Address: "0x1efF47bc3a10a45D4B230B5d10E37751FE6AA718"}}, Threshold: 1},
			fmt.Sprint(base):   {Signers: []model.Signer{{Address: unknownAddr}}, Threshold: 1},
		},
		DestinationVerifiers: map[model.DestinationSelector]string{
			fmt.Sprint(ethereum): "0x1000000000000000000000000000000000000002",
			fmt.Sprint(canton):   "canton-verifier",
		},
	}
}

func verifierSpec() string {
	return "schemaVersion = 1\ntype = \"ccvcommitteeverifier\"\n"
}

// executorSpec renders a ccvexecutor job spec with its config under key (appConfig or executorConfig).
func executorSpec(key string, pools map[ChainSelector][]string) string {
	var inner strings.Builder
	for _, chain := range sortedKeys(pools) {
		fmt.Fprintf(&inner, "[chain_configuration.%d]\nexecutor_pool = [\"%s\"]\n", chain, strings.Join(pools[chain], "\", \""))
	}
	return fmt.Sprintf("schemaVersion = 1\ntype = \"ccvexecutor\"\n%s = '''\n%s'''\n", key, inner.String())
}

func committeesFor(inv *Inventory, chain ChainSelector) []Committee {
	var out []Committee
	for _, c := range inv.Committees {
		if c.SourceChain == chain {
			out = append(out, c)
		}
	}
	return out
}

func committeeFor(t *testing.T, inv *Inventory, source string, chain ChainSelector) Committee {
	t.Helper()
	i := slices.IndexFunc(inv.Committees, func(c Committee) bool { return c.Source == source && c.SourceChain == chain })
	require.GreaterOrEqual(t, i, 0, "no %s committee for %d", source, chain)
	return inv.Committees[i]
}

func memberFor(t *testing.T, c Committee, addr string) Member {
	t.Helper()
	i := slices.IndexFunc(c.Members, func(m Member) bool { return m.SignerAddress == addr })
	require.GreaterOrEqual(t, i, 0, "no member %s", addr)
	return c.Members[i]
}

func nodeFor(t *testing.T, inv *Inventory, id string) Node {
	t.Helper()
	i := slices.IndexFunc(inv.Nodes, func(n Node) bool { return n.ID == id })
	require.GreaterOrEqual(t, i, 0, "no node %s", id)
	return inv.Nodes[i]
}

func nopFor(t *testing.T, inv *Inventory, alias string) NOP {
	t.Helper()
	i := slices.IndexFunc(inv.NOPs, func(n NOP) bool { return n.Alias == alias })
	require.GreaterOrEqual(t, i, 0, "no NOP %s", alias)
	return inv.NOPs[i]
}

func executorPoolFor(t *testing.T, inv *Inventory, pool string, chain ChainSelector) ExecutorPool {
	t.Helper()
	i := slices.IndexFunc(inv.ExecutorPools, func(p ExecutorPool) bool { return p.Pool == pool && p.Chain == chain })
	require.GreaterOrEqual(t, i, 0, "no pool %s on %d", pool, chain)
	return inv.ExecutorPools[i]
}
