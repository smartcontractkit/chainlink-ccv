package jobs

import (
	"context"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/clclient"
	sdkclient "github.com/smartcontractkit/chainlink/deployment/environment/web/sdk/client"
)

// NewSDKClient creates an SDK GraphQL client from a ChainlinkClient's credentials.
func NewSDKClient(ctx context.Context, clClient *clclient.ChainlinkClient) (sdkclient.Client, error) {
	return sdkclient.NewWithContext(ctx, clClient.URL(), sdkclient.Credentials{
		Email:    clClient.Config.Email,
		Password: clClient.Config.Password,
	})
}

// ListPendingJobProposalSpecs returns spec IDs for all pending job proposals.
func ListPendingJobProposalSpecs(ctx context.Context, c sdkclient.Client) ([]string, error) {
	jds, err := c.ListJobDistributors(ctx)
	if err != nil {
		return nil, err
	}

	var pendingSpecs []string
	for _, fm := range jds.FeedsManagers.Results {
		for _, jp := range fm.JobProposals {
			if jp.Status == "PENDING" && jp.LatestSpec.Id != "" {
				pendingSpecs = append(pendingSpecs, jp.LatestSpec.Id)
			}
		}
	}
	return pendingSpecs, nil
}
