package jobs

import (
	"context"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/clclient"
)

func AcceptPendingJobs(ctx context.Context, clientLookup *NodeSetClientLookup) error {
	if clientLookup == nil || clientLookup.Len() == 0 {
		Plog.Debug().Msg("No CL clients available, skipping job acceptance")
		return nil
	}

	clients := clientLookup.AllClients()
	Plog.Info().Int("numNodes", len(clients)).Msg("Accepting pending job proposals on all nodes")

	totalAccepted := 0
	for i, clClient := range clients {
		pendingSpecs, err := listPendingJobProposalSpecs(ctx, clClient)
		if err != nil {
			Plog.Warn().Int("nodeIndex", i).Err(err).Msg("Failed to list pending job proposals")
			continue
		}

		if len(pendingSpecs) == 0 {
			Plog.Debug().Int("nodeIndex", i).Msg("No pending job proposals found")
			continue
		}

		Plog.Info().Int("nodeIndex", i).Int("numPending", len(pendingSpecs)).Msg("Found pending job proposals")

		for _, specID := range pendingSpecs {
			if err := approveJobProposalSpec(ctx, clClient, specID); err != nil {
				Plog.Warn().Int("nodeIndex", i).Str("specID", specID).Err(err).Msg("Failed to approve job proposal")
				continue
			}
			totalAccepted++
			Plog.Debug().Int("nodeIndex", i).Str("specID", specID).Msg("Approved job proposal")
		}
	}

	Plog.Info().Int("totalAccepted", totalAccepted).Msg("Finished accepting pending job proposals")
	return nil
}

func listPendingJobProposalSpecs(ctx context.Context, clClient *clclient.ChainlinkClient) ([]string, error) {
	gqlClient, err := NewSDKClient(ctx, clClient)
	if err != nil {
		return nil, err
	}
	return ListPendingJobProposalSpecs(ctx, gqlClient)
}

func approveJobProposalSpec(ctx context.Context, clClient *clclient.ChainlinkClient, specID string) error {
	gqlClient, err := NewSDKClient(ctx, clClient)
	if err != nil {
		return err
	}
	_, err = gqlClient.ApproveJobProposalSpec(ctx, specID, true)
	return err
}
