package jobs

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc/credentials/insecure"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain/jd"
	csav1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/csa"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/clclient"
	ctf_jd "github.com/smartcontractkit/chainlink-testing-framework/framework/components/jd"
	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
	sdkclient "github.com/smartcontractkit/chainlink/deployment/environment/web/sdk/client"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/deployments/changesets"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
)

type JDInfrastructure struct {
	JDOutput       *ctf_jd.Output
	OffchainClient offchain.Client
	NodeIDMap      map[string]string // alias -> JD node ID (needed for JD operations)
}

func (j *JDInfrastructure) GetNodeIDs() []string {
	if j == nil || j.NodeIDMap == nil {
		return nil
	}
	nodeIDs := make([]string, 0, len(j.NodeIDMap))
	for _, nodeID := range j.NodeIDMap {
		nodeIDs = append(nodeIDs, nodeID)
	}
	return nodeIDs
}

type JDInfrastructureConfig struct {
	JDInput  *ctf_jd.Input
	NodeSets []*ns.Input
}

func StartJDInfrastructure(ctx context.Context, cfg JDInfrastructureConfig) (*JDInfrastructure, error) {
	if cfg.JDInput == nil {
		Plog.Debug().Msg("JD input is nil, skipping JD infrastructure setup")
		return nil, nil
	}

	if os.Getenv("JD_IMAGE") != "" {
		cfg.JDInput.Image = os.Getenv("JD_IMAGE")
	}

	jdOutput, err := ctf_jd.NewWithContext(ctx, cfg.JDInput)
	if err != nil {
		return nil, fmt.Errorf("failed to start JD container: %w", err)
	}

	jdConfig := jd.JDConfig{
		GRPC:  jdOutput.ExternalGRPCUrl,
		WSRPC: jdOutput.ExternalWSRPCUrl,
		Creds: insecure.NewCredentials(),
	}
	jdClient, err := jd.NewJDClient(jdConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create JD client: %w", err)
	}

	Plog.Info().
		Str("jdGRPC", jdOutput.ExternalGRPCUrl).
		Msg("JD infrastructure started")

	return &JDInfrastructure{
		JDOutput:       jdOutput,
		OffchainClient: jdClient,
		NodeIDMap:      make(map[string]string),
	}, nil
}

func RegisterNodesWithJD(ctx context.Context, infra *JDInfrastructure, clientLookup *NodeSetClientLookup, nopAliases []string) error {
	if len(nopAliases) == 0 {
		return nil
	}

	if infra == nil || infra.OffchainClient == nil {
		return fmt.Errorf("JD infrastructure required to register %d nodes but not available", len(nopAliases))
	}

	if clientLookup == nil || clientLookup.Len() == 0 {
		return fmt.Errorf("no CL clients available to register %d nodes", len(nopAliases))
	}

	for _, alias := range nopAliases {
		clClient, ok := clientLookup.GetClient(alias)
		if !ok {
			return fmt.Errorf("no CL client found for NOP alias %s", alias)
		}

		csaKeys, _, err := clClient.MustReadCSAKeys()
		if err != nil {
			return fmt.Errorf("failed to read CSA keys for node %s: %w", alias, err)
		}
		if len(csaKeys.Data) == 0 {
			return fmt.Errorf("no CSA keys found for node %s", alias)
		}
		csaKey := strings.TrimPrefix(csaKeys.Data[0].Attributes.PublicKey, "csa_")

		resp, err := infra.OffchainClient.RegisterNode(ctx, &nodev1.RegisterNodeRequest{
			Name:      alias,
			PublicKey: csaKey,
		})
		if err != nil {
			return fmt.Errorf("failed to register node %s with JD: %w", alias, err)
		}

		infra.NodeIDMap[alias] = resp.Node.Id
		Plog.Info().
			Str("nopAlias", alias).
			Str("nodeID", resp.Node.Id).
			Str("csaKey", csaKey).
			Msg("Registered node with JD")
	}

	Plog.Info().
		Int("numNodes", len(infra.NodeIDMap)).
		Msg("All nodes registered with JD")

	return nil
}

func GetJDCSAPublicKey(ctx context.Context, jdClient offchain.Client) (string, error) {
	keypairResp, err := jdClient.GetKeypair(ctx, &csav1.GetKeypairRequest{})
	if err != nil {
		return "", fmt.Errorf("failed to get JD CSA keypair: %w", err)
	}
	if keypairResp.Keypair == nil {
		return "", fmt.Errorf("JD CSA keypair is nil")
	}
	return keypairResp.Keypair.PublicKey, nil
}

func createChainConfigsInNode(ctx context.Context, clClient *clclient.ChainlinkClient, chainIDs []string) error {
	gqlClient, err := NewSDKClient(ctx, clClient)
	if err != nil {
		return fmt.Errorf("failed to create SDK client: %w", err)
	}

	jds, err := gqlClient.ListJobDistributors(ctx)
	if err != nil {
		return fmt.Errorf("failed to list job distributors: %w", err)
	}
	if len(jds.FeedsManagers.Results) == 0 {
		return fmt.Errorf("no feeds manager found")
	}
	fmID := jds.FeedsManagers.Results[0].Id

	p2pPeerID, err := gqlClient.FetchP2PPeerID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get P2P peer ID: %w", err)
	}

	ocr2KeyBundleID, err := gqlClient.FetchOCR2KeyBundleID(ctx, "EVM")
	if err != nil {
		return fmt.Errorf("failed to get OCR2 key bundle ID: %w", err)
	}

	if len(chainIDs) == 0 {
		return fmt.Errorf("no chain IDs provided")
	}
	accountAddr, err := gqlClient.FetchAccountAddress(ctx, chainIDs[0])
	if err != nil {
		return fmt.Errorf("failed to get EVM account address: %w", err)
	}

	Plog.Debug().
		Str("feedsManagerID", fmID).
		Str("p2pPeerID", *p2pPeerID).
		Str("ocr2KeyBundleID", ocr2KeyBundleID).
		Str("accountAddr", *accountAddr).
		Int("numChains", len(chainIDs)).
		Msg("Creating chain configs in CL node")

	for _, chainID := range chainIDs {
		_, err := gqlClient.CreateJobDistributorChainConfig(ctx, sdkclient.JobDistributorChainConfigInput{
			JobDistributorID: fmID,
			ChainID:          chainID,
			ChainType:        "EVM",
			AccountAddr:      *accountAddr,
			AdminAddr:        *accountAddr,
			Ocr2Enabled:      true,
			Ocr2P2PPeerID:    *p2pPeerID,
			Ocr2KeyBundleID:  ocr2KeyBundleID,
			Ocr2Plugins:      `{"commit":false,"execute":false,"median":false,"mercury":false}`,
		})
		if err != nil {
			return fmt.Errorf("failed to create chain config for chain %s: %w", chainID, err)
		}
	}

	Plog.Info().
		Int("numChains", len(chainIDs)).
		Msg("Finished creating chain configs in CL node")

	return nil
}

func CreateFeedsManagerInNode(ctx context.Context, clClient *clclient.ChainlinkClient, jdWSRPCUrl, jdCSAPublicKey string) (string, error) {
	gqlClient, err := NewSDKClient(ctx, clClient)
	if err != nil {
		return "", fmt.Errorf("failed to create SDK client: %w", err)
	}

	fmID, err := gqlClient.CreateJobDistributor(ctx, sdkclient.JobDistributorInput{
		Name:      "Job Distributor",
		Uri:       jdWSRPCUrl,
		PublicKey: jdCSAPublicKey,
	})
	if err != nil {
		return "", err
	}
	if fmID != "" {
		Plog.Info().
			Str("id", fmID).
			Str("uri", jdWSRPCUrl).
			Msg("Created Feeds Manager in CL node")
	} else {
		Plog.Debug().Msg("Feeds Manager already exists in CL node")
	}
	return fmID, nil
}

func waitForNodeConnection(ctx context.Context, jdClient offchain.Client, nodeID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for node %s to connect", nodeID)
			}

			nodeResp, err := jdClient.GetNode(ctx, &nodev1.GetNodeRequest{Id: nodeID})
			if err != nil {
				Plog.Debug().Str("nodeID", nodeID).Err(err).Msg("Failed to get node status, retrying...")
				continue
			}

			if nodeResp.Node != nil && nodeResp.Node.IsConnected {
				Plog.Info().Str("nodeID", nodeID).Msg("Node connected to JD")
				return nil
			}

			Plog.Debug().Str("nodeID", nodeID).Bool("isConnected", nodeResp.Node.IsConnected).Msg("Node not yet connected, waiting...")
		}
	}
}

func waitForChainConfigs(ctx context.Context, jdClient offchain.Client, nodeID string, timeout time.Duration, chainIDs []string) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for chain configs for node %s", nodeID)
			}

			chainConfigsResp, err := jdClient.ListNodeChainConfigs(ctx, &nodev1.ListNodeChainConfigsRequest{
				Filter: &nodev1.ListNodeChainConfigsRequest_Filter{
					NodeIds: []string{nodeID},
				},
			})
			if err != nil {
				Plog.Debug().Str("nodeID", nodeID).Err(err).Msg("Failed to list chain configs, retrying...")
				continue
			}

			foundChainConfigs := make(map[string]bool)
			for _, chainID := range chainIDs {
				foundChainConfigs[chainID] = false
			}

			for _, chainConfig := range chainConfigsResp.ChainConfigs {
				if chainConfig.Ocr2Config != nil &&
					chainConfig.Ocr2Config.OcrKeyBundle != nil &&
					chainConfig.Ocr2Config.OcrKeyBundle.OnchainSigningAddress != "" {
					Plog.Info().
						Str("nodeID", nodeID).
						Str("chainType", chainConfig.Chain.Type.String()).
						Str("signingAddress", chainConfig.Ocr2Config.OcrKeyBundle.OnchainSigningAddress).
						Msg("Chain config with OCR2 keys available")
					foundChainConfigs[chainConfig.Chain.Id] = true
				}
			}

			allFound := true
			for _, found := range foundChainConfigs {
				if !found {
					allFound = false
					break
				}
			}

			if allFound {
				return nil
			}

			Plog.Debug().Str("nodeID", nodeID).Int("configCount", len(chainConfigsResp.ChainConfigs)).Msg("No OCR2 chain configs yet, waiting...")
		}
	}
}

func ConnectNodesToJD(ctx context.Context, infra *JDInfrastructure, clientLookup *NodeSetClientLookup, chainIDs []string) error {
	if infra == nil || infra.OffchainClient == nil {
		Plog.Debug().Msg("JD infrastructure not available, skipping node connection")
		return nil
	}

	if clientLookup == nil || clientLookup.Len() == 0 {
		Plog.Debug().Msg("No CL clients available, skipping node connection")
		return nil
	}

	jdPublicKey, err := GetJDCSAPublicKey(ctx, infra.OffchainClient)
	if err != nil {
		return fmt.Errorf("failed to get JD CSA public key: %w", err)
	}

	Plog.Info().
		Str("jdPublicKey", jdPublicKey).
		Str("jdWSRPCUrl", infra.JDOutput.InternalWSRPCUrl).
		Msg("Got JD CSA public key, creating Feeds Managers in CL nodes")

	clients := clientLookup.AllClients()
	for i, clClient := range clients {
		_, err := CreateFeedsManagerInNode(ctx, clClient, infra.JDOutput.InternalWSRPCUrl, jdPublicKey)
		if err != nil {
			return fmt.Errorf("failed to create Feeds Manager in node %d: %w", i, err)
		}
	}

	Plog.Info().Msg("Waiting for all nodes to connect to JD...")

	connectionTimeout := 60 * time.Second
	chainConfigTimeout := 60 * time.Second
	for alias, nodeID := range infra.NodeIDMap {
		if err := waitForNodeConnection(ctx, infra.OffchainClient, nodeID, connectionTimeout); err != nil {
			Plog.Warn().
				Str("nopAlias", alias).
				Str("nodeID", nodeID).
				Err(err).
				Msg("Node failed to connect to JD within timeout")
			return fmt.Errorf("node %s failed to connect to JD within timeout", nodeID)
		}

		clClient, ok := clientLookup.GetClient(alias)
		if !ok {
			Plog.Warn().
				Str("nopAlias", alias).
				Msg("No CL client found for alias, skipping chain config creation")
			return fmt.Errorf("no CL client found for alias %s", alias)
		}

		if err := createChainConfigsInNode(ctx, clClient, chainIDs); err != nil {
			Plog.Warn().
				Str("nopAlias", alias).
				Err(err).
				Msg("Failed to create chain configs in node")
			return fmt.Errorf("failed to create chain configs in node %s: %w", alias, err)
		}

		if err := waitForChainConfigs(ctx, infra.OffchainClient, nodeID, chainConfigTimeout, chainIDs); err != nil {
			Plog.Warn().
				Str("nopAlias", alias).
				Str("nodeID", nodeID).
				Err(err).
				Msg("Chain configs not available within timeout - OCR keys won't be fetchable from JD")
		}
	}

	Plog.Info().Msg("All nodes connected to JD with chain configs")
	return nil
}

func SyncAndVerifyJobProposals(e *deployment.Environment) error {
	if e.Offchain == nil {
		Plog.Debug().Msg("JD infrastructure not available, skipping job verification")
		return nil
	}

	if e.DataStore == nil {
		return fmt.Errorf("datastore is required for job proposal verification")
	}

	allJobs, err := deployments.GetAllJobs(e.DataStore)
	if err != nil {
		return fmt.Errorf("failed to get all jobs: %w", err)
	}

	clJobCount := 0
	for _, nopJobs := range allJobs {
		for _, job := range nopJobs {
			if job.Mode == shared.NOPModeCL {
				clJobCount++
			}
		}
	}

	if clJobCount == 0 {
		Plog.Info().Msg("No CL mode jobs to verify")
		return nil
	}

	output, err := changesets.SyncJobProposals().Apply(*e, changesets.SyncJobProposalsCfg{})
	if err != nil {
		return fmt.Errorf("failed to sync job proposals: %w", err)
	}

	updatedJobs, err := deployments.GetAllJobs(output.DataStore.Seal())
	if err != nil {
		return fmt.Errorf("failed to get updated jobs: %w", err)
	}

	pendingCLJobs := make([]string, 0)
	for nopAlias, nopJobs := range updatedJobs {
		for jobID, job := range nopJobs {
			if job.Mode == shared.NOPModeCL && job.LatestStatus() != shared.JobProposalStatusApproved {
				pendingCLJobs = append(pendingCLJobs,
					fmt.Sprintf("%s/%s: %s", nopAlias, jobID, job.LatestStatus()))
			}
		}
	}

	if len(pendingCLJobs) > 0 {
		return fmt.Errorf("not all CL mode job proposals were accepted: %v", pendingCLJobs)
	}

	Plog.Info().Msg("All CL mode job proposals are approved")
	return nil
}
