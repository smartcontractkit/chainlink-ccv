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
			latestVersion := 0
			var latestStatus string
			var latestId string
			for _, jps := range jp.Specs {
				if jps.Version > latestVersion {
					latestVersion = jps.Version
					latestStatus = string(jps.Status)
					latestId = jps.Id
				}
			}
			if latestStatus == "PENDING" && latestVersion != 0 {
				pendingSpecs = append(pendingSpecs, latestId)
			}
		}
	}
	return pendingSpecs, nil
}
