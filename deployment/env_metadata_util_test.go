package deployment

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	indexerconfig "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/cctp"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/lombard"

	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

func quorum(addr string, threshold uint8, signers ...string) *model.QuorumConfig {
	qc := &model.QuorumConfig{SourceVerifierAddress: addr, Threshold: threshold}
	for _, s := range signers {
		qc.Signers = append(qc.Signers, model.Signer{Address: s})
	}

	return qc
}

// TestMergeAggregatorConfig_AccumulatesAcrossChains is the core scaling case:
// running the aggregator config generation once per chain must accumulate into a
// single committee rather than replacing it.
func TestMergeAggregatorConfig_AccumulatesAcrossChains(t *testing.T) {
	t.Parallel()

	ds := datastore.NewMemoryDataStore()

	// First per-chain run: source chain 1, destination chain 10.
	require.NoError(t, MergeAggregatorConfig(ds, "aggregator-1", &model.Committee{
		QuorumConfigs:        map[string]*model.QuorumConfig{"1": quorum("0xsrc1", 1, "0xa")},
		DestinationVerifiers: map[string]string{"10": "0xdest10"},
	}))

	// Second per-chain run: source chain 2, destination chain 20.
	require.NoError(t, MergeAggregatorConfig(ds, "aggregator-1", &model.Committee{
		QuorumConfigs:        map[string]*model.QuorumConfig{"2": quorum("0xsrc2", 2, "0xb")},
		DestinationVerifiers: map[string]string{"20": "0xdest20"},
	}))

	got, err := GetAggregatorConfig(ds.Seal(), "aggregator-1")
	require.NoError(t, err)

	// Both chains' configs survive — the second run did not clobber the first.
	require.Len(t, got.QuorumConfigs, 2)
	require.Equal(t, "0xsrc1", got.QuorumConfigs["1"].SourceVerifierAddress)
	require.Equal(t, "0xsrc2", got.QuorumConfigs["2"].SourceVerifierAddress)
	require.Equal(t, map[string]string{"10": "0xdest10", "20": "0xdest20"}, got.DestinationVerifiers)
}

// TestMergeAggregatorConfig_OverwritesConflictingChain verifies an upsert: a
// re-run for an already-stored chain replaces that chain's entry.
func TestMergeAggregatorConfig_OverwritesConflictingChain(t *testing.T) {
	t.Parallel()

	ds := datastore.NewMemoryDataStore()
	require.NoError(t, MergeAggregatorConfig(ds, "aggregator-1", &model.Committee{
		QuorumConfigs:        map[string]*model.QuorumConfig{"1": quorum("0xold", 1, "0xa")},
		DestinationVerifiers: map[string]string{"10": "0xold"},
	}))
	require.NoError(t, MergeAggregatorConfig(ds, "aggregator-1", &model.Committee{
		QuorumConfigs:        map[string]*model.QuorumConfig{"1": quorum("0xnew", 3, "0xa", "0xb", "0xc")},
		DestinationVerifiers: map[string]string{"10": "0xnew"},
	}))

	got, err := GetAggregatorConfig(ds.Seal(), "aggregator-1")
	require.NoError(t, err)
	require.Len(t, got.QuorumConfigs, 1)
	require.Equal(t, "0xnew", got.QuorumConfigs["1"].SourceVerifierAddress)
	require.Equal(t, uint8(3), got.QuorumConfigs["1"].Threshold)
	require.Equal(t, "0xnew", got.DestinationVerifiers["10"])
}

// TestMergeAggregatorConfig_FirstRunStoresAsIs verifies merge into an empty
// datastore behaves like a plain save.
func TestMergeAggregatorConfig_FirstRunStoresAsIs(t *testing.T) {
	t.Parallel()

	ds := datastore.NewMemoryDataStore()
	require.NoError(t, MergeAggregatorConfig(ds, "aggregator-1", &model.Committee{
		QuorumConfigs:        map[string]*model.QuorumConfig{"1": quorum("0xsrc1", 1, "0xa")},
		DestinationVerifiers: map[string]string{"10": "0xdest10"},
	}))

	got, err := GetAggregatorConfig(ds.Seal(), "aggregator-1")
	require.NoError(t, err)
	require.Len(t, got.QuorumConfigs, 1)
	require.Equal(t, "0xsrc1", got.QuorumConfigs["1"].SourceVerifierAddress)
}

// TestMergeAggregatorConfig_PreservesOtherIdentifiers verifies accumulating into
// one service identifier never disturbs another.
func TestMergeAggregatorConfig_PreservesOtherIdentifiers(t *testing.T) {
	t.Parallel()

	ds := datastore.NewMemoryDataStore()
	require.NoError(t, SaveAggregatorConfig(ds, "aggregator-2", &model.Committee{
		QuorumConfigs:        map[string]*model.QuorumConfig{"9": quorum("0x9", 1, "0xz")},
		DestinationVerifiers: map[string]string{},
	}))
	require.NoError(t, MergeAggregatorConfig(ds, "aggregator-1", &model.Committee{
		QuorumConfigs:        map[string]*model.QuorumConfig{"1": quorum("0x1", 1, "0xa")},
		DestinationVerifiers: map[string]string{},
	}))

	sealed := ds.Seal()

	got1, err := GetAggregatorConfig(sealed, "aggregator-1")
	require.NoError(t, err)
	require.Equal(t, "0x1", got1.QuorumConfigs["1"].SourceVerifierAddress)

	got2, err := GetAggregatorConfig(sealed, "aggregator-2")
	require.NoError(t, err)
	require.Equal(t, "0x9", got2.QuorumConfigs["9"].SourceVerifierAddress)
}

// TestMergeCommittees covers the pure merge helper, including nil arguments.
func TestMergeCommittees(t *testing.T) {
	t.Parallel()

	incoming := &model.Committee{
		QuorumConfigs:        map[string]*model.QuorumConfig{"1": quorum("0x1", 1)},
		DestinationVerifiers: map[string]string{"10": "0x10"},
	}

	require.Same(t, incoming, mergeCommittees(nil, incoming))

	existing := &model.Committee{
		QuorumConfigs:        map[string]*model.QuorumConfig{"2": quorum("0x2", 1)},
		DestinationVerifiers: map[string]string{"20": "0x20"},
	}
	require.Same(t, existing, mergeCommittees(existing, nil))

	merged := mergeCommittees(existing, incoming)
	require.Len(t, merged.QuorumConfigs, 2)
	require.Len(t, merged.DestinationVerifiers, 2)
	// Inputs are not mutated.
	require.Len(t, existing.QuorumConfigs, 1)
	require.Len(t, incoming.QuorumConfigs, 1)
}

// TestMergeIndexerConfig_AccumulatesAndUpsertsByName verifies indexer verifiers
// accumulate across runs and are upserted by Name.
func TestMergeIndexerConfig_AccumulatesAndUpsertsByName(t *testing.T) {
	t.Parallel()

	ds := datastore.NewMemoryDataStore()
	require.NoError(t, MergeIndexerConfig(ds, "indexer-1", &indexerconfig.GeneratedConfig{
		Verifier: []indexerconfig.GeneratedVerifierConfig{
			{Name: "committee-1", IssuerAddresses: []string{"0xold"}},
		},
	}))
	require.NoError(t, MergeIndexerConfig(ds, "indexer-1", &indexerconfig.GeneratedConfig{
		Verifier: []indexerconfig.GeneratedVerifierConfig{
			{Name: "committee-1", IssuerAddresses: []string{"0xnew"}}, // upsert by Name
			{Name: "committee-2", IssuerAddresses: []string{"0xccc"}}, // appended
		},
	}))

	got, err := GetIndexerConfig(ds.Seal(), "indexer-1")
	require.NoError(t, err)
	require.Len(t, got.Verifier, 2)

	byName := map[string][]string{}
	for _, v := range got.Verifier {
		byName[v.Name] = v.IssuerAddresses
	}
	require.Equal(t, []string{"0xnew"}, byName["committee-1"])
	require.Equal(t, []string{"0xccc"}, byName["committee-2"])
}

// TestMergeTokenVerifierConfig_AccumulatesPerChain is the core token-verifier
// scaling case: per-chain runs accumulate the committee on-ramp/RMN maps and each
// verifier's per-chain address maps, rather than replacing the whole config.
func TestMergeTokenVerifierConfig_AccumulatesPerChain(t *testing.T) {
	t.Parallel()

	ds := datastore.NewMemoryDataStore()

	// First per-chain run: chain 1, with a CCTP and a Lombard verifier.
	require.NoError(t, MergeTokenVerifierConfig(ds, "token-1", &token.Config{
		PyroscopeURL:    "http://pyroscope",
		CommitteeConfig: chainaccess.CommitteeConfig{OnRampAddresses: map[string]string{"1": "0xonramp1"}, RMNRemoteAddresses: map[string]string{"1": "0xrmn1"}},
		TokenVerifiers: []token.VerifierConfig{
			{VerifierID: "cctp-q", Type: "cctp", Version: "2.0", CCTPConfig: &cctp.CCTPConfig{
				Verifiers:         map[string]any{"1": "0xcctp1"},
				VerifierResolvers: map[string]any{"1": "0xcctpres1"},
			}},
			{VerifierID: "lombard-q", Type: "lombard", Version: "1.0", LombardConfig: &lombard.LombardConfig{
				VerifierResolvers: map[string]any{"1": "0xlomres1"},
			}},
		},
	}))

	// Second per-chain run: chain 2, same verifier IDs.
	require.NoError(t, MergeTokenVerifierConfig(ds, "token-1", &token.Config{
		PyroscopeURL:    "http://pyroscope",
		CommitteeConfig: chainaccess.CommitteeConfig{OnRampAddresses: map[string]string{"2": "0xonramp2"}, RMNRemoteAddresses: map[string]string{"2": "0xrmn2"}},
		TokenVerifiers: []token.VerifierConfig{
			{VerifierID: "cctp-q", Type: "cctp", Version: "2.0", CCTPConfig: &cctp.CCTPConfig{
				Verifiers:         map[string]any{"2": "0xcctp2"},
				VerifierResolvers: map[string]any{"2": "0xcctpres2"},
			}},
			{VerifierID: "lombard-q", Type: "lombard", Version: "1.0", LombardConfig: &lombard.LombardConfig{
				VerifierResolvers: map[string]any{"2": "0xlomres2"},
			}},
		},
	}))

	got, err := GetTokenVerifierConfig(ds.Seal(), "token-1")
	require.NoError(t, err)

	// Committee maps cover both chains. The deprecated RMN map is preserved across merges so
	// configs stored before the derivation cutover keep their entries.
	require.Equal(t, map[string]string{"1": "0xonramp1", "2": "0xonramp2"}, got.OnRampAddresses)
	require.Equal(t, map[string]string{"1": "0xrmn1", "2": "0xrmn2"}, got.RMNRemoteAddresses)

	// Still exactly two verifiers (merged by VerifierID, not duplicated).
	require.Len(t, got.TokenVerifiers, 2)
	byID := map[string]token.VerifierConfig{}
	for _, vc := range got.TokenVerifiers {
		byID[vc.VerifierID] = vc
	}

	// Each verifier's per-chain maps accumulate across both runs.
	gotCCTP := byID["cctp-q"].CCTPConfig
	require.Equal(t, map[string]any{"1": "0xcctp1", "2": "0xcctp2"}, gotCCTP.Verifiers)
	require.Equal(t, map[string]any{"1": "0xcctpres1", "2": "0xcctpres2"}, gotCCTP.VerifierResolvers)
	gotLombard := byID["lombard-q"].LombardConfig
	require.Equal(t, map[string]any{"1": "0xlomres1", "2": "0xlomres2"}, gotLombard.VerifierResolvers)
}

func testProposal(id string, revision int64, status shared.JobProposalStatus) shared.ProposalRevision {
	return shared.ProposalRevision{ProposalID: id, Revision: revision, Status: status, Spec: "spec-" + id}
}

// TestJobInfo_PruneProposals pins the retention rule: persisted jobs keep the
// active proposal and the latest by revision, so the env-metadata blob does not
// grow with JD's full proposal history.
func TestJobInfo_PruneProposals(t *testing.T) {
	t.Parallel()

	t.Run("keeps active and latest when they differ", func(t *testing.T) {
		t.Parallel()

		job := shared.JobInfo{
			ActiveProposalID: "p1",
			Proposals: map[string]shared.ProposalRevision{
				"p1": testProposal("p1", 1, shared.JobProposalStatusApproved),
				"p2": testProposal("p2", 2, shared.JobProposalStatusRejected),
				"p3": testProposal("p3", 3, shared.JobProposalStatusPending),
			},
		}
		job.PruneProposals()

		require.Len(t, job.Proposals, 2)
		require.Contains(t, job.Proposals, "p1")
		require.Contains(t, job.Proposals, "p3")
	})

	t.Run("keeps only latest when active is the latest", func(t *testing.T) {
		t.Parallel()

		job := shared.JobInfo{
			ActiveProposalID: "p3",
			Proposals: map[string]shared.ProposalRevision{
				"p1": testProposal("p1", 1, shared.JobProposalStatusApproved),
				"p3": testProposal("p3", 3, shared.JobProposalStatusApproved),
			},
		}
		job.PruneProposals()

		require.Len(t, job.Proposals, 1)
		require.Contains(t, job.Proposals, "p3")
	})

	t.Run("keeps only latest when no active is set", func(t *testing.T) {
		t.Parallel()

		job := shared.JobInfo{
			Proposals: map[string]shared.ProposalRevision{
				"p1": testProposal("p1", 1, shared.JobProposalStatusRevoked),
				"p2": testProposal("p2", 2, shared.JobProposalStatusRevoked),
			},
		}
		job.PruneProposals()

		require.Len(t, job.Proposals, 1)
		require.Contains(t, job.Proposals, "p2")
	})

	t.Run("ignores an active ID that is not stored", func(t *testing.T) {
		t.Parallel()

		job := shared.JobInfo{
			ActiveProposalID: "missing",
			Proposals: map[string]shared.ProposalRevision{
				"p1": testProposal("p1", 1, shared.JobProposalStatusApproved),
				"p2": testProposal("p2", 2, shared.JobProposalStatusApproved),
			},
		}
		job.PruneProposals()

		require.Len(t, job.Proposals, 1)
		require.Contains(t, job.Proposals, "p2")
	})

	t.Run("single proposal and empty proposals are no-ops", func(t *testing.T) {
		t.Parallel()

		one := shared.JobInfo{Proposals: map[string]shared.ProposalRevision{"p1": testProposal("p1", 1, shared.JobProposalStatusPending)}}
		one.PruneProposals()
		require.Len(t, one.Proposals, 1)

		empty := shared.JobInfo{}
		empty.PruneProposals()
		require.Empty(t, empty.Proposals)
	})

	t.Run("does not mutate a map shared with the caller", func(t *testing.T) {
		t.Parallel()

		proposals := map[string]shared.ProposalRevision{
			"p1": testProposal("p1", 1, shared.JobProposalStatusApproved),
			"p3": testProposal("p3", 3, shared.JobProposalStatusPending),
		}
		job := shared.JobInfo{ActiveProposalID: "p1", Proposals: proposals}
		job.PruneProposals()

		require.Len(t, job.Proposals, 2) // pruned copy
		require.Len(t, proposals, 2)     // caller's map untouched
	})
}

// TestSaveJob_PrunesProposalHistory verifies the persistence seam prunes: what
// lands in the datastore is the retention set, not the full history.
func TestSaveJob_PrunesProposalHistory(t *testing.T) {
	t.Parallel()

	ds := datastore.NewMemoryDataStore()
	job := shared.JobInfo{
		JobID:            "job-1",
		NOPAlias:         "nop-1",
		Spec:             "current-spec",
		ActiveProposalID: "p1",
		Proposals: map[string]shared.ProposalRevision{
			"p1": testProposal("p1", 1, shared.JobProposalStatusApproved),
			"p2": testProposal("p2", 2, shared.JobProposalStatusRejected),
			"p3": testProposal("p3", 3, shared.JobProposalStatusPending),
		},
	}
	require.NoError(t, SaveJob(ds, job))

	got, err := GetJob(ds.Seal(), "nop-1", "job-1")
	require.NoError(t, err)
	require.Len(t, got.Proposals, 2)
	require.Contains(t, got.Proposals, "p1")
	require.Contains(t, got.Proposals, "p3")
	require.Equal(t, "p3", got.LatestProposal().ProposalID)
}

// TestSaveJobs_PrunesProposalHistory covers the batch seam used by
// manage-job-proposals.
func TestSaveJobs_PrunesProposalHistory(t *testing.T) {
	t.Parallel()

	ds := datastore.NewMemoryDataStore()
	jobs := []shared.JobInfo{
		{
			JobID:            "job-1",
			NOPAlias:         "nop-1",
			ActiveProposalID: "p2",
			Proposals: map[string]shared.ProposalRevision{
				"p1": testProposal("p1", 1, shared.JobProposalStatusApproved),
				"p2": testProposal("p2", 2, shared.JobProposalStatusApproved),
				"p3": testProposal("p3", 3, shared.JobProposalStatusPending),
			},
		},
	}
	require.NoError(t, SaveJobs(ds, jobs))

	got, err := GetAllJobs(ds.Seal())
	require.NoError(t, err)
	require.Len(t, got["nop-1"]["job-1"].Proposals, 2)
	require.Contains(t, got["nop-1"]["job-1"].Proposals, "p2")
	require.Contains(t, got["nop-1"]["job-1"].Proposals, "p3")
}
