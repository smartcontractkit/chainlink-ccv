package committeeverifier

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	ledgerv2admin "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2/admin"
	"github.com/testcontainers/testcontainers-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/devenv/internal/util"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader/canton"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	"github.com/smartcontractkit/go-daml/pkg/auth"
)

// CantonModifier is a function that modifies a testcontainers.ContainerRequest for canton.
// TODO: this should get moved to chainlink-canton and registered as a modifier prior to calling NewVerifier.
func CantonModifier(req testcontainers.ContainerRequest, verifierInput *Input, outputs []*blockchain.Output) (testcontainers.ContainerRequest, error) {
	const (
		DefaultCantonCommitteVerifierImage = "cantoncommittee-verifier:dev"
	)

	// Use the canton committee verifier image to properly read from Canton.
	req.Image = DefaultCantonCommitteVerifierImage

	// Update name to reflect chain family.
	req.Name = fmt.Sprintf("canton-%s", verifierInput.ContainerName)

	// Marshal the canton config into TOML bytes.
	cantonConfigBytes, err := hydrateAndMarshalCantonConfig(verifierInput, outputs)
	if err != nil {
		return req, fmt.Errorf("failed to hydrate and marshal canton config: %w", err)
	}

	// Save the canton config bytes to a temporary file.
	confDir := util.CCVConfigDir()
	cantonConfigFilePath := filepath.Join(confDir,
		fmt.Sprintf("canton-%s-config-%d.toml", verifierInput.CommitteeName, verifierInput.NodeIndex+1))
	if err := os.WriteFile(cantonConfigFilePath, cantonConfigBytes, 0o644); err != nil {
		return req, fmt.Errorf("failed to write canton config to file: %w", err)
	}

	// Mount the canton config file.
	//nolint:staticcheck // we're still using it...
	req.Mounts = append(req.Mounts, testcontainers.BindMount(
		cantonConfigFilePath,
		canton.DefaultCantonConfigPath,
	))

	return req, nil
}

// hydrateAndMarshalCantonConfig hydrates the canton config with the full party ID for the CCIPOwnerParty.
func hydrateAndMarshalCantonConfig(in *Input, outputs []*blockchain.Output) ([]byte, error) {
	for _, output := range outputs {
		if output.Family != chainsel.FamilyCanton {
			continue
		}

		chainDetails, err := chainsel.GetChainDetailsByChainIDAndFamily(output.ChainID, output.Family)
		if err != nil {
			return nil, fmt.Errorf("failed to get chain details for chain %s, family %s: %w", output.ChainID, output.Family, err)
		}

		strSelector := strconv.FormatUint(chainDetails.ChainSelector, 10)
		cantonConfig, ok := in.CantonConfigs.ReaderConfigs[strSelector]
		if !ok {
			return nil, fmt.Errorf("no canton config found for chain %s, please update the config appropriately if you're using canton", strSelector)
		}
		if cantonConfig.CCIPOwnerParty == "" {
			return nil, fmt.Errorf("CCIPOwnerParty is not set for chain %s, please update the config appropriately if you're using canton", strSelector)
		}
		if cantonConfig.CCIPMessageSentTemplateID == "" {
			return nil, fmt.Errorf("CCIPMessageSentTemplateID is not set for chain %s, please update the config appropriately if you're using canton", strSelector)
		}

		// Get the full party ID (name + hex id) from the canton participant.
		// TODO: how to support multiple participants?
		grpcURL := output.NetworkSpecificData.CantonEndpoints.Participants[0].GRPCLedgerAPIURL
		jwt := output.NetworkSpecificData.CantonEndpoints.Participants[0].JWT
		if grpcURL == "" || jwt == "" {
			return nil, fmt.Errorf("GRPC ledger API URL or JWT is not set for chain %s, please update the config appropriately if you're using canton", strSelector)
		}

		// find the party that starts with the prefix that is listed in the canton config.
		conn, err := grpc.NewClient(grpcURL, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithPerRPCCredentials(auth.NewBearerToken(jwt)))
		if err != nil {
			return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
		}
		resp, err := ledgerv2admin.NewPartyManagementServiceClient(conn).ListKnownParties(context.Background(), &ledgerv2admin.ListKnownPartiesRequest{})
		if err != nil {
			return nil, fmt.Errorf("failed to get user: %w", err)
		}

		authority := grpcURL
		if idx := strings.LastIndex(authority, ":"); idx != -1 {
			authority = authority[:idx]
		}

		var found bool
		for _, partyDetail := range resp.PartyDetails {
			if strings.HasPrefix(partyDetail.GetParty(), cantonConfig.CCIPOwnerParty) {
				in.CantonConfigs.ReaderConfigs[strSelector] = canton.ReaderConfig{
					CCIPOwnerParty:            partyDetail.GetParty(),
					CCIPMessageSentTemplateID: cantonConfig.CCIPMessageSentTemplateID,
					Authority:                 authority,
				}
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("expected CCIPOwnerParty %s not found for canton chain %s, please update the config appropriately if you're using canton", cantonConfig.CCIPOwnerParty, strSelector)
		}
	}

	// Marshal the canton config into TOML.
	cantonConfigBytes, err := toml.Marshal(in.CantonConfigs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal canton config: %w", err)
	}

	return cantonConfigBytes, nil
}
