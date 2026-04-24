package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sethvargo/go-retry"

	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/clclient"
	sdkclient "github.com/smartcontractkit/chainlink/deployment/environment/web/sdk/client"
)

// RotateOCR2KeyBundle creates a new EVM OCR2 key bundle on the CL node, updates
// the JD chain configs for the provided chain IDs to reference the new bundle, and
// returns the previous and new on-chain signing addresses.
//
// The function:
//  1. Queries JD for the current on-chain signing address (old address).
//  2. Creates a new OCR2 key bundle on the CL node.
//  3. Deletes all existing feeds-manager chain configs for the provided chain IDs.
//  4. Re-creates them with the new bundle ID.
//  5. Waits for JD to reflect the new signing address.
//
// chainIDs must be the decimal string chain IDs (e.g. "1", "100") that already have
// a chain config registered for nodeID in JD.
func RotateOCR2KeyBundle(
	ctx context.Context,
	clClient *clclient.ChainlinkClient,
	jdClient offchain.Client,
	nodeID string,
	chainIDs []string,
) (oldSigningAddr, newSigningAddr string, err error) {
	// 1. Capture current signing address before mutation.
	oldSigningAddr, err = fetchSigningAddrFromJD(ctx, jdClient, nodeID)
	if err != nil {
		return "", "", fmt.Errorf("rotate key: fetch current signing address: %w", err)
	}

	// 2. Create new OCR2 key bundle on the CL node.
	newKey, _, err := clClient.CreateOCR2Key("evm")
	if err != nil {
		return "", "", fmt.Errorf("rotate key: create OCR2 key: %w", err)
	}
	newBundleID := newKey.Data.ID

	// 3. Build SDK client (authenticated) to manage feeds-manager chain configs.
	gqlClient, err := NewSDKClient(ctx, clClient)
	if err != nil {
		return "", "", fmt.Errorf("rotate key: create SDK client: %w", err)
	}

	// 4. Get feeds manager ID and existing chain config IDs.
	fmID, err := getFeedsManagerID(ctx, gqlClient)
	if err != nil {
		return "", "", fmt.Errorf("rotate key: get feeds manager: %w", err)
	}

	chainConfigIDs, err := listFMChainConfigIDsForChains(ctx, clClient, fmID, chainIDs)
	if err != nil {
		return "", "", fmt.Errorf("rotate key: list chain config IDs: %w", err)
	}

	// 5. Delete existing chain configs.
	for _, id := range chainConfigIDs {
		if err := gqlClient.DeleteJobDistributorChainConfig(ctx, id); err != nil {
			return "", "", fmt.Errorf("rotate key: delete chain config %s: %w", id, err)
		}
	}

	// 6. Re-create chain configs with new bundle ID.
	p2pPeerID, err := gqlClient.FetchP2PPeerID(ctx)
	if err != nil {
		return "", "", fmt.Errorf("rotate key: fetch P2P peer ID: %w", err)
	}

	for _, chainID := range chainIDs {
		accountAddr, err := gqlClient.FetchAccountAddress(ctx, chainID)
		if err != nil {
			return "", "", fmt.Errorf("rotate key: fetch account address for chain %s: %w", chainID, err)
		}
		input := sdkclient.JobDistributorChainConfigInput{
			JobDistributorID: fmID,
			ChainID:          chainID,
			ChainType:        "EVM",
			AccountAddr:      *accountAddr,
			AdminAddr:        *accountAddr,
			Ocr2Enabled:      true,
			Ocr2P2PPeerID:    *p2pPeerID,
			Ocr2KeyBundleID:  newBundleID,
			Ocr2Plugins:      `{"commit":false,"execute":false,"median":false,"mercury":false}`,
		}
		if err := createAndVerifyChainConfig(ctx, gqlClient, jdClient, nodeID, input); err != nil {
			return "", "", fmt.Errorf("rotate key: create chain config for chain %s: %w", chainID, err)
		}
	}

	// 7. Wait for JD to reflect the new signing address.
	newSigningAddr, err = waitForNewSigningAddr(ctx, jdClient, nodeID, oldSigningAddr)
	if err != nil {
		return "", "", fmt.Errorf("rotate key: wait for new signing address: %w", err)
	}

	return oldSigningAddr, newSigningAddr, nil
}

// fetchSigningAddrFromJD returns the on-chain signing address for the first EVM chain config found in JD.
func fetchSigningAddrFromJD(ctx context.Context, jdClient offchain.Client, nodeID string) (string, error) {
	resp, err := jdClient.ListNodeChainConfigs(ctx, &nodev1.ListNodeChainConfigsRequest{
		Filter: &nodev1.ListNodeChainConfigsRequest_Filter{NodeIds: []string{nodeID}},
	})
	if err != nil {
		return "", fmt.Errorf("list node chain configs: %w", err)
	}
	for _, cfg := range resp.ChainConfigs {
		if cfg.Ocr2Config != nil && cfg.Ocr2Config.OcrKeyBundle != nil {
			if addr := cfg.Ocr2Config.OcrKeyBundle.OnchainSigningAddress; addr != "" {
				return addr, nil
			}
		}
	}
	return "", errors.New("no EVM chain config with signing address found for node")
}

// waitForNewSigningAddr polls JD until the node's signing address differs from oldAddr.
func waitForNewSigningAddr(ctx context.Context, jdClient offchain.Client, nodeID, oldAddr string) (string, error) {
	backoff := retry.WithMaxDuration(90*time.Second, retry.NewExponential(2*time.Second))
	var newAddr string
	err := retry.Do(ctx, backoff, func(ctx context.Context) error {
		addr, err := fetchSigningAddrFromJD(ctx, jdClient, nodeID)
		if err != nil {
			return retry.RetryableError(err)
		}
		if strings.EqualFold(addr, oldAddr) {
			return retry.RetryableError(errors.New("signing address not yet updated in JD"))
		}
		newAddr = addr
		return nil
	})
	return newAddr, err
}

// getFeedsManagerID returns the first feeds manager ID visible to this CL node.
func getFeedsManagerID(ctx context.Context, gqlClient sdkclient.Client) (string, error) {
	jds, err := gqlClient.ListJobDistributors(ctx)
	if err != nil {
		return "", fmt.Errorf("list job distributors: %w", err)
	}
	if len(jds.FeedsManagers.Results) == 0 {
		return "", errors.New("no feeds manager found")
	}
	return jds.FeedsManagers.Results[0].Id, nil
}

// fmChainConfigEntry is a minimal representation of a feeds-manager chain config.
type fmChainConfigEntry struct {
	ID      string `json:"id"`
	ChainID string `json:"chainID"`
}

// listFMChainConfigIDsForChains returns the graphql IDs of existing feeds-manager chain configs
// that match the given chain IDs. It authenticates against the CL node and issues a raw
// GraphQL query because the SDK client's FeedsManagerParts fragment omits chainConfigs.
func listFMChainConfigIDsForChains(ctx context.Context, clClient *clclient.ChainlinkClient, fmID string, chainIDs []string) ([]string, error) {
	cookie, err := clSessionCookie(ctx, clClient.URL(), clClient.Config.Email, clClient.Config.Password)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	entries, err := queryFMChainConfigs(ctx, clClient.URL(), cookie, fmID)
	if err != nil {
		return nil, err
	}

	chainIDSet := make(map[string]struct{}, len(chainIDs))
	for _, c := range chainIDs {
		chainIDSet[c] = struct{}{}
	}

	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if _, ok := chainIDSet[e.ChainID]; ok {
			ids = append(ids, e.ID)
		}
	}
	return ids, nil
}

// clSessionCookie authenticates with the CL node REST API and returns the session cookie value.
func clSessionCookie(ctx context.Context, baseURL, email, password string) (string, error) {
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/sessions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST /sessions: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("POST /sessions returned %d", resp.StatusCode)
	}
	// Use the raw Set-Cookie header as the SDK client does.
	raw := resp.Header.Get("Set-Cookie")
	if raw == "" {
		return "", errors.New("no Set-Cookie header in session response")
	}
	return strings.SplitN(raw, ";", 2)[0], nil
}

// queryFMChainConfigs issues a raw GraphQL query to retrieve chain config IDs for a feeds manager.
func queryFMChainConfigs(ctx context.Context, baseURL, cookie, fmID string) ([]fmChainConfigEntry, error) {
	const gql = `{"query":"query GetFMCC($id:ID!){feedsManager(id:$id){...on FeedsManager{chainConfigs{id chainID}}}}","variables":{"id":"%s"}}`
	body := strings.NewReader(fmt.Sprintf(gql, fmID))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/query", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookie)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST /query: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	var result struct {
		Data struct {
			FeedsManager struct {
				ChainConfigs []fmChainConfigEntry `json:"chainConfigs"`
			} `json:"feedsManager"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode graphql response: %w", err)
	}
	if len(result.Errors) > 0 {
		msgs := make([]string, len(result.Errors))
		for i, e := range result.Errors {
			msgs[i] = e.Message
		}
		return nil, fmt.Errorf("graphql errors: %s", strings.Join(msgs, "; "))
	}
	return result.Data.FeedsManager.ChainConfigs, nil
}
