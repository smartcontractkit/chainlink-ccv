package canton

import (
	"encoding/hex"
	"fmt"
	"math/big"
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

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	devenvcanton "github.com/smartcontractkit/chainlink-ccv/devenv/canton"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader/canton"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const (
	createArg1 = "ccipOwner"
	createArg2 = "partyOwner"

	// TODO: this is hardcoded for now but should be derived from the deployment somehow.
	partyName = "participant1-localparty-1"

	packageID         = "json-tests"
	moduleName        = "Main"
	entityName        = "TestRouter"
	ccipSendChoice    = "CCIPSend"
	numMessages       = 3
	destChainSelector = 1337
)

// version in hex: 0x49ff34ed
// obtained from https://github.com/smartcontractkit/chainlink-ccip/blob/de2b2252d2003c99abeb98d122fc9fbe248009bb/chains/evm/contracts/ccvs/CommitteeVerifier.sol#L35-L36.
var committeeVerifierVersion = []byte{0x49, 0xff, 0x34, 0xed}

// Start the environment required for this test using:
// ccv up env-canton-evm.toml
// from the build/devenv directory.
func TestCantonSourceReader(t *testing.T) {
	in, err := ccv.Load[ccv.Cfg]([]string{"../../../env-canton-evm-out.toml"})
	require.NoError(t, err)

	var cantonChain *blockchain.Input
	for _, bc := range in.Blockchains {
		if bc.Type == blockchain.TypeCanton {
			cantonChain = bc
			break
		}
	}
	require.NotNil(t, cantonChain, "need at least one canton chain for this test")

	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	grpcURL := cantonChain.Out.NetworkSpecificData.CantonEndpoints.Participants[0].GRPCLedgerAPIURL
	require.NotEmpty(t, grpcURL)
	jwt := cantonChain.Out.NetworkSpecificData.CantonEndpoints.Participants[0].JWT
	require.NotEmpty(t, jwt)

	helper, err := devenvcanton.NewHelperFromBlockchainInput(grpcURL, jwt)
	require.NoError(t, err)
	ts := newTestSetup(t, helper)

	// Assert that the parties were created and are known to the ledger.
	knownParties, err := ts.helper.ListKnownParties(t.Context())
	require.NoError(t, err)
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
	err = ts.helper.UploadDar(t.Context(), "json-tests-0.0.1.dar")
	require.NoError(t, err)
	knownPackages, err := ts.helper.ListKnownPackages(t.Context())
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(knownPackages), 1)
	require.True(t, slices.ContainsFunc(knownPackages, func(p *ledgerv2admin.PackageDetails) bool {
		return p.GetName() == packageID
	}))
	var ccipMessageSentTemplateID *ledgerv2.Identifier
	for _, pkg := range knownPackages {
		if pkg.GetName() == packageID {
			ccipMessageSentTemplateID = &ledgerv2.Identifier{
				PackageId:  "#" + pkg.GetName(),
				ModuleName: "Main",
				EntityName: "CCIPMessageSent",
			}
			break
		}
	}
	require.NotNil(t, ccipMessageSentTemplateID)
	t.Logf("ccipMessageSentTemplateID being used: %s", ccipMessageSentTemplateID.String())

	// Deploy the TestRouter contract.
	// TODO: ideally ccipOwner and partyOwner are separate parties, but we need to figure out the auth for that.
	ccipOwner, partyOwner := party, party
	createResp := ts.createTestRouter(t, ccipOwner, partyOwner)
	require.NotNil(t, createResp)

	sourceReader, err := canton.NewSourceReader(
		grpcURL,
		jwt,
		canton.ReaderConfig{
			CCIPOwnerParty:            ccipOwner,
			CCIPMessageSentTemplateID: fmt.Sprintf("%s:%s:%s", ccipMessageSentTemplateID.PackageId, ccipMessageSentTemplateID.ModuleName, ccipMessageSentTemplateID.EntityName),
		},
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	latestBefore, finalizedBefore, err := sourceReader.LatestAndFinalizedBlock(t.Context())
	require.NoError(t, err)
	require.NotNil(t, latestBefore)
	require.NotNil(t, finalizedBefore)
	t.Logf("latest block: %d, finalized block: %d before sending messages", latestBefore.Number, finalizedBefore.Number)

	// Create a few CCIPMessageSent "events" by exercising the appropriate choice on the TestRouter contract.
	seqNr := int64(1)
	contractID := ts.getContractID(t, createResp.GetUpdateId(), party)
	messages := make([]protocol.Message, numMessages)
	for i := range numMessages {
		msg := newMessage(t, seqNr)
		messages[i] = msg
		ts.ccipSend(t,
			contractID,
			partyOwner,
			destChainSelector,
			seqNr,
			msg.MustMessageID(),
			mustEncodeMessage(t, msg),
			[][]byte{
				committeeVerifierVersion, // committee verifier only returns the version in the verifierBlob.
			},
		)
		seqNr++
	}

	latestAfter, finalizedAfter, err := sourceReader.LatestAndFinalizedBlock(t.Context())
	require.NoError(t, err)
	require.NotNil(t, latestAfter)
	require.NotNil(t, finalizedAfter)
	t.Logf("latest block: %d, finalized block: %d after sending messages", latestAfter.Number, finalizedAfter.Number)

	// query for the CCIPMessageSent events in between before and after
	events, err := sourceReader.FetchMessageSentEvents(t.Context(), new(big.Int).SetUint64(latestBefore.Number), new(big.Int).SetUint64(latestAfter.Number))
	require.NoError(t, err)
	require.Equal(t, len(events), numMessages)

	// assert that we can find the messages in the events
	for _, event := range events {
		found := false
		for _, msg := range messages {
			if msg.MustMessageID() == event.MessageID {
				found = true
				break
			}
		}
		require.True(t, found)
	}
}

func newMessage(t *testing.T, seqNr int64) protocol.Message {
	msg, err := protocol.NewMessage(
		protocol.ChainSelector(1337),
		protocol.ChainSelector(2337),
		protocol.SequenceNumber(seqNr),
		protocol.UnknownAddress([]byte("onramp address")),
		protocol.UnknownAddress([]byte("offramp address")),
		10,
		200_000,
		100_000,
		protocol.Bytes32{},
		protocol.UnknownAddress([]byte("sender address")),
		protocol.UnknownAddress([]byte("receiver address")),
		[]byte("dest blob"),
		[]byte("message data payload"),
		nil,
	)
	require.NoError(t, err)

	return *msg
}

func mustEncodeMessage(t *testing.T, msg protocol.Message) []byte {
	encoded, err := msg.Encode()
	require.NoError(t, err)
	return encoded
}

func getSub(t *testing.T, jwt string) string {
	claims := jwtv5.MapClaims{}
	_, _, err := jwtv5.NewParser().ParseUnverified(jwt, claims)
	require.NoError(t, err)
	require.NotNil(t, claims["sub"])

	return claims["sub"].(string)
}

type testSetup struct {
	helper *devenvcanton.Helper
}

func (ts *testSetup) getContractID(t *testing.T, updateID, party string) string {
	resp, err := ts.helper.GetUpdateServiceClient().GetUpdateById(ts.helper.AuthCtx(t.Context()), &ledgerv2.GetUpdateByIdRequest{
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

	resp, err := ts.helper.GetCommandServiceClient().SubmitAndWait(ts.helper.AuthCtx(t.Context()), &ledgerv2.SubmitAndWaitRequest{
		Commands: &ledgerv2.Commands{
			CommandId: uuid.New().String(),
			UserId:    ts.helper.GetUserID(),
			ActAs:     []string{partyOwnerParty},
			ReadAs:    []string{partyOwnerParty},
			Commands: []*ledgerv2.Command{
				{
					Command: &ledgerv2.Command_Exercise{
						Exercise: &ledgerv2.ExerciseCommand{
							TemplateId: &ledgerv2.Identifier{
								PackageId:  "#" + packageID,
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
	resp, err := ts.helper.GetCommandServiceClient().SubmitAndWait(ts.helper.AuthCtx(t.Context()), &ledgerv2.SubmitAndWaitRequest{
		Commands: &ledgerv2.Commands{
			CommandId: uuid.New().String(),
			UserId:    ts.helper.GetUserID(),
			ActAs:     []string{ccipOwnerParty},
			ReadAs:    []string{ccipOwnerParty},
			Commands: []*ledgerv2.Command{
				{
					Command: &ledgerv2.Command_Create{
						Create: &ledgerv2.CreateCommand{
							TemplateId: &ledgerv2.Identifier{
								PackageId:  "#" + packageID,
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

func newTestSetup(t *testing.T, helper *devenvcanton.Helper) *testSetup {
	return &testSetup{
		helper: helper,
	}
}
