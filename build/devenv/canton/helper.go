package canton

import (
	"context"
	"fmt"
	"os"

	ledgerv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2"
	ledgerv2admin "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2/admin"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/smartcontractkit/go-daml/pkg/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Helper is a helper for working with Canton in devenv contexts.
// It uses insecure gRPC connections so it should not be used in production settings.
type Helper struct {
	partyMgmtClient    ledgerv2admin.PartyManagementServiceClient
	pkgMgmtClient      ledgerv2admin.PackageManagementServiceClient
	commandClient      ledgerv2.CommandServiceClient
	updatesClient      ledgerv2.UpdateServiceClient
	stateServiceClient ledgerv2.StateServiceClient
	jwt                string
	userID             string
	partyID            string
}

func (h *Helper) GetUserID() string {
	return h.userID
}

func (h *Helper) GetPartyManagementServiceClient() ledgerv2admin.PartyManagementServiceClient {
	return h.partyMgmtClient
}

func (h *Helper) GetPackageManagementServiceClient() ledgerv2admin.PackageManagementServiceClient {
	return h.pkgMgmtClient
}

func (h *Helper) GetCommandServiceClient() ledgerv2.CommandServiceClient {
	return h.commandClient
}

func (h *Helper) GetUpdateServiceClient() ledgerv2.UpdateServiceClient {
	return h.updatesClient
}

func (h *Helper) ListKnownParties(ctx context.Context) ([]*ledgerv2admin.PartyDetails, error) {
	resp, err := h.partyMgmtClient.ListKnownParties(ctx, &ledgerv2admin.ListKnownPartiesRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetPartyDetails(), nil
}

func (h *Helper) ListKnownPackages(ctx context.Context) ([]*ledgerv2admin.PackageDetails, error) {
	resp, err := h.pkgMgmtClient.ListKnownPackages(ctx, &ledgerv2admin.ListKnownPackagesRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetPackageDetails(), nil
}

func (h *Helper) UploadDar(ctx context.Context, darPath string) error {
	dar, err := os.ReadFile(darPath)
	if err != nil {
		return err
	}
	_, err = h.pkgMgmtClient.UploadDarFile(ctx, &ledgerv2admin.UploadDarFileRequest{
		DarFile:      dar,
		SubmissionId: uuid.New().String(),
	})
	return err
}

func NewHelperFromBlockchainInput(ctx context.Context, grpcURL, jwt string) (*Helper, error) {
	userID, err := getSub(jwt)
	if err != nil {
		return nil, fmt.Errorf("failed to get sub from JWT: %w", err)
	}

	conn, err := grpc.NewClient(grpcURL, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithPerRPCCredentials(auth.NewBearerToken(jwt)))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	// Get primary party
	resp, err := ledgerv2admin.NewUserManagementServiceClient(conn).GetUser(ctx, &ledgerv2admin.GetUserRequest{UserId: userID})
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if resp.GetUser().GetPrimaryParty() == "" {
		return nil, fmt.Errorf("user has no primary party")
	}

	return &Helper{
		partyMgmtClient:    ledgerv2admin.NewPartyManagementServiceClient(conn),
		pkgMgmtClient:      ledgerv2admin.NewPackageManagementServiceClient(conn),
		commandClient:      ledgerv2.NewCommandServiceClient(conn),
		updatesClient:      ledgerv2.NewUpdateServiceClient(conn),
		stateServiceClient: ledgerv2.NewStateServiceClient(conn),
		jwt:                jwt,
		userID:             userID,
		partyID:            resp.GetUser().GetPrimaryParty(),
	}, nil
}

func getSub(jwt string) (string, error) {
	claims := jwtv5.MapClaims{}
	_, _, err := jwtv5.NewParser().ParseUnverified(jwt, claims)
	if err != nil {
		return "", fmt.Errorf("failed to parse JWT: %w", err)
	}
	if claims["sub"] == nil {
		return "", fmt.Errorf("sub claim is not set in JWT")
	}

	return claims["sub"].(string), nil
}
