package canton

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	ledgerv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2"
	ledgerv2admin "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2/admin"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader/canton"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

const (
	createArg1 = "ccipOwner"
	createArg2 = "partyOwner"

	// TODO: this is hardcoded for now but should be derived from the deployment somehow.
	partyName = "participant1-localparty-1"

	packageId         = "#json-tests"
	moduleName        = "Main"
	entityName        = "TestRouter"
	ccipSendChoice    = "CCIPSend"
	numMessages       = 3
	destChainSelector = 1337
)

// Start the environment required for this test using:
// ccv start-blockchains env-canton-single-validator.toml
// from the build/devenv directory.
func TestCantonSourceReader(t *testing.T) {
	in, err := ccv.Load[ccv.Cfg]([]string{"../../../env-canton-single-validator-out.toml"})
	require.NoError(t, err)

	bcOutput := in.Blockchains[0].Out

	jwt := bcOutput.NetworkSpecificData.CantonEndpoints.Participants[0].JWT
	require.NotEmpty(t, jwt)

	// the subject in the jwt is the user id that will be used to submit the commands.
	userID := getSub(t, jwt)
	require.NotEmpty(t, userID)
	t.Logf("sub (user id to use): %s", userID)

	grpcURL := bcOutput.NetworkSpecificData.CantonEndpoints.Participants[0].GRPCLedgerAPIURL
	require.NotEmpty(t, grpcURL)

	ts := newTestSetup(t, grpcURL, jwt, userID)

	// Assert that the parties were created and are known to the ledger.
	knownParties := ts.listKnownParties(t)
	require.GreaterOrEqual(t, len(knownParties), 1)
	// Find the party that corresponds to the JWT token that we have
	var party string
	for _, theParty := range knownParties {
		if strings.HasPrefix(theParty.GetParty(), partyName) {
			party = theParty.GetParty()
			break
		}
	}
	require.NotEmpty(t, party)
	t.Logf("found party: %s", party)

	// Upload the DAR file containing the TestRouter contract and any required dependencies.
	ts.uploadDar(t, "json-tests-0.0.1.dar")
	knownPackages := ts.listKnownPackages(t)
	require.GreaterOrEqual(t, len(knownPackages), 1)
	require.True(t, slices.ContainsFunc(knownPackages, func(p *ledgerv2admin.PackageDetails) bool {
		return p.GetName() == "json-tests"
	}))

	// Deploy the TestRouter contract.
	// TODO: ideally ccipOwner and partyOwner are separate parties, but we need to figure out the auth for that.
	ccipOwner, partyOwner := party, party
	createResp := ts.createTestRouter(t, ccipOwner, partyOwner)
	require.NotNil(t, createResp)

	contractID := ts.getContractID(t, createResp.GetUpdateId(), party)

	// Create a few CCIPMessageSent "events" by exercising the appropriate choice on the TestRouter contract.
	seqNr := int64(1)
	for range numMessages {
		var messageID protocol.Bytes32
		binary.BigEndian.PutUint64(messageID[:], uint64(seqNr))
		encodedMessage := fmt.Appendf(nil, "message %d", seqNr)
		verifierBlobs := [][]byte{
			fmt.Appendf(nil, "verifier blob A for message %d", seqNr),
			fmt.Appendf(nil, "verifier blob B for message %d", seqNr),
		}
		ts.ccipSend(t, contractID, partyOwner, destChainSelector, seqNr, messageID, encodedMessage, verifierBlobs)
		seqNr++
	}

	sourceReader, err := canton.NewSourceReader(
		grpcURL,
		jwt,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	latest, finalized, err := sourceReader.LatestAndFinalizedBlock(t.Context())
	require.NoError(t, err)
	require.NotNil(t, latest)
	require.NotNil(t, finalized)
	t.Logf("latest block: %d", latest.Number)
	t.Logf("finalized block: %d", finalized.Number)
}

func getSub(t *testing.T, jwt string) string {
	claims := jwtv5.MapClaims{}
	_, _, err := jwtv5.NewParser().ParseUnverified(jwt, claims)
	require.NoError(t, err)
	require.NotNil(t, claims["sub"])

	return claims["sub"].(string)
}

type testSetup struct {
	partyMgmtClient ledgerv2admin.PartyManagementServiceClient
	pkgMgmtClient   ledgerv2admin.PackageManagementServiceClient
	commandClient   ledgerv2.CommandServiceClient
	updatesClient   ledgerv2.UpdateServiceClient
	jwt             string
	userID          string
}

func (ts *testSetup) getContractID(t *testing.T, updateID, party string) string {
	ctx := ts.authCtx(t)

	resp, err := ts.updatesClient.GetUpdateById(ctx, &ledgerv2.GetUpdateByIdRequest{
		UpdateId: updateID,
		UpdateFormat: &ledgerv2.UpdateFormat{
			IncludeTransactions: &ledgerv2.TransactionFormat{
				TransactionShape: ledgerv2.TransactionShape_TRANSACTION_SHAPE_ACS_DELTA,
				EventFormat: &ledgerv2.EventFormat{
					FiltersByParty: map[string]*ledgerv2.Filters{
						party: {
							Cumulative: []*ledgerv2.CumulativeFilter{
								{
									IdentifierFilter: &ledgerv2.CumulativeFilter_WildcardFilter{
										WildcardFilter: &ledgerv2.WildcardFilter{
											IncludeCreatedEventBlob: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	events := resp.GetTransaction().GetEvents()
	var contractID string
	for _, event := range events {
		created := event.GetCreated()
		if created != nil {
			contractID = created.GetContractId()
		}
	}
	require.NotEmpty(t, contractID)

	return contractID
}

func (ts *testSetup) ccipSend(
	t *testing.T,
	contractID,
	partyOwnerParty string,
	destChainSelector int64,
	sequenceNumber int64,
	messageID protocol.Bytes32,
	encodedMessage []byte,
	verifierBlobs [][]byte,
) *ledgerv2.SubmitAndWaitResponse {
	verifierBlobElements := make([]*ledgerv2.Value, len(verifierBlobs))
	for i, blob := range verifierBlobs {
		verifierBlobElements[i] = &ledgerv2.Value{
			Sum: &ledgerv2.Value_Text{
				Text: hex.EncodeToString(blob),
			},
		}
	}

	ctx := ts.authCtx(t)

	resp, err := ts.commandClient.SubmitAndWait(ctx, &ledgerv2.SubmitAndWaitRequest{
		Commands: &ledgerv2.Commands{
			CommandId: uuid.New().String(),
			UserId:    ts.userID,
			ActAs:     []string{partyOwnerParty},
			ReadAs:    []string{partyOwnerParty},
			Commands: []*ledgerv2.Command{
				{
					Command: &ledgerv2.Command_Exercise{
						Exercise: &ledgerv2.ExerciseCommand{
							TemplateId: &ledgerv2.Identifier{
								PackageId:  packageId,
								ModuleName: moduleName,
								EntityName: entityName,
							},
							ContractId: contractID,
							Choice:     ccipSendChoice,
							ChoiceArgument: &ledgerv2.Value{
								Sum: &ledgerv2.Value_Record{
									Record: &ledgerv2.Record{
										Fields: []*ledgerv2.RecordField{
											{
												Label: "destChainSelector",
												Value: &ledgerv2.Value{
													Sum: &ledgerv2.Value_Numeric{
														Numeric: fmt.Sprintf("%d", destChainSelector),
													},
												},
											},
											{
												Label: "sequenceNumber",
												Value: &ledgerv2.Value{
													Sum: &ledgerv2.Value_Numeric{
														Numeric: fmt.Sprintf("%d", sequenceNumber),
													},
												},
											},
											{
												Label: "messageId",
												Value: &ledgerv2.Value{
													Sum: &ledgerv2.Value_Text{
														Text: hex.EncodeToString(messageID[:]),
													},
												},
											},
											{
												Label: "encodedMessage",
												Value: &ledgerv2.Value{
													Sum: &ledgerv2.Value_Text{
														Text: hex.EncodeToString(encodedMessage),
													},
												},
											},
											{
												Label: "verifierBlobs",
												Value: &ledgerv2.Value{
													Sum: &ledgerv2.Value_List{
														List: &ledgerv2.List{
															Elements: verifierBlobElements,
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	return resp
}

func (ts *testSetup) createTestRouter(t *testing.T, ccipOwnerParty, partyOwnerParty string) *ledgerv2.SubmitAndWaitResponse {
	ctx := ts.authCtx(t)

	resp, err := ts.commandClient.SubmitAndWait(ctx, &ledgerv2.SubmitAndWaitRequest{
		Commands: &ledgerv2.Commands{
			CommandId: uuid.New().String(),
			UserId:    ts.userID,
			ActAs:     []string{ccipOwnerParty},
			ReadAs:    []string{ccipOwnerParty},
			Commands: []*ledgerv2.Command{
				{
					Command: &ledgerv2.Command_Create{
						Create: &ledgerv2.CreateCommand{
							TemplateId: &ledgerv2.Identifier{
								PackageId:  packageId,
								ModuleName: moduleName,
								EntityName: entityName,
							},
							CreateArguments: &ledgerv2.Record{
								Fields: []*ledgerv2.RecordField{
									{
										Label: createArg1,
										Value: &ledgerv2.Value{
											Sum: &ledgerv2.Value_Party{
												Party: ccipOwnerParty,
											},
										},
									},
									{
										Label: createArg2,
										Value: &ledgerv2.Value{
											Sum: &ledgerv2.Value_Party{
												Party: partyOwnerParty,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	return resp
}

func (ts *testSetup) listKnownParties(t *testing.T) []*ledgerv2admin.PartyDetails {
	ctx := ts.authCtx(t)

	resp, err := ts.partyMgmtClient.ListKnownParties(ctx, &ledgerv2admin.ListKnownPartiesRequest{})
	require.NoError(t, err)

	return resp.GetPartyDetails()
}

func (ts *testSetup) uploadDar(t *testing.T, darPath string) {
	ctx := ts.authCtx(t)

	dar, err := os.ReadFile(darPath)
	require.NoError(t, err)

	_, err = ts.pkgMgmtClient.UploadDarFile(ctx, &ledgerv2admin.UploadDarFileRequest{
		DarFile:      dar,
		SubmissionId: uuid.New().String(),
	})
	require.NoError(t, err)
}

func (ts *testSetup) listKnownPackages(t *testing.T) []*ledgerv2admin.PackageDetails {
	ctx := ts.authCtx(t)

	resp, err := ts.pkgMgmtClient.ListKnownPackages(ctx, &ledgerv2admin.ListKnownPackagesRequest{})
	require.NoError(t, err)

	return resp.GetPackageDetails()
}

func (ts *testSetup) authCtx(t *testing.T) context.Context {
	return metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", ts.jwt)))
}

func newTestSetup(t *testing.T, grpcURL, jwt, userID string) *testSetup {
	conn, err := grpc.NewClient(grpcURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	pmsClient := ledgerv2admin.NewPartyManagementServiceClient(conn)
	pkgMgmtClient := ledgerv2admin.NewPackageManagementServiceClient(conn)
	commandClient := ledgerv2.NewCommandServiceClient(conn)
	updatesClient := ledgerv2.NewUpdateServiceClient(conn)

	return &testSetup{
		partyMgmtClient: pmsClient,
		pkgMgmtClient:   pkgMgmtClient,
		commandClient:   commandClient,
		updatesClient:   updatesClient,
		jwt:             jwt,
		userID:          userID,
	}
}
