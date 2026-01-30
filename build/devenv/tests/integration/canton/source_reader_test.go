package canton

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	ledgerv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2"
	ledgerv2admin "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2/admin"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	offrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/offramp"
	onrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/onramp"
	routeroperations "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	devenvcanton "github.com/smartcontractkit/chainlink-ccv/devenv/canton"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader/canton"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
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
	configPath := "../../../env-canton-evm-out.toml"
	in, err := ccv.LoadOutput[ccv.Cfg](configPath)
	require.NoError(t, err)

	var cantonChain *blockchain.Input
	for _, bc := range in.Blockchains {
		if bc.Type == blockchain.TypeCanton {
			cantonChain = bc
			break
		}
	}
	require.NotNil(t, cantonChain, "need at least one canton chain for this test")

	var evmChain *blockchain.Input
	for _, bc := range in.Blockchains {
		if bc.Type == blockchain.TypeAnvil {
			evmChain = bc
			break
		}
	}
	require.NotNil(t, evmChain, "need at least one evm chain for this test")

	cantonDetails, err := chain_selectors.GetChainDetailsByChainIDAndFamily(cantonChain.ChainID, chain_selectors.FamilyCanton)
	require.NoError(t, err)

	evmDetails, err := chain_selectors.GetChainDetailsByChainIDAndFamily(evmChain.ChainID, chain_selectors.FamilyEVM)
	require.NoError(t, err)

	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	lib, err := ccv.NewLib(l, configPath, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	chains, err := lib.ChainsMap(ctx)
	require.NoError(t, err)
	destChain := chains[evmDetails.ChainSelector]
	require.NotNil(t, destChain)

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
	ts := newTestSetup(helper)

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

	// Check that the expected package is uploaded.
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
		logger.Test(t),
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

	addresses := getRelevantAddresses(t, in, cantonDetails, evmDetails)
	for i := range numMessages {
		msg := newMessage(
			t,
			protocol.ChainSelector(cantonDetails.ChainSelector),
			protocol.ChainSelector(evmDetails.ChainSelector),
			seqNr,
			addresses.cantonOnRamp,
			addresses.evmOffRamp,
			addresses.evmReceiver,
			[]protocol.UnknownAddress{addresses.cantonDefaultVerifierAddress},
			addresses.cantonExecutorAddress,
		)
		messages[i] = msg
		t.Logf("sending message seqNr %d messageID %s", seqNr, msg.MustMessageID().String())
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
			[]testReceipt{
				{
					// TODO: this isn't correct, because for canton the issuer is the CCVId.
					// We need to set the "verifier address" in the verifier to be the CCVId rather than
					// the address of the committee_verifier.ResolverType from the DataStore.
					Issuer:            addresses.defaultVerifierIssuer,
					DestGasLimit:      100000,
					DestBytesOverhead: 500,
					FeeTokenAmount:    "1000000.",
					ExtraArgs:         []byte{},
				},
				{
					Issuer:            addresses.executorIssuer,
					DestGasLimit:      0,
					DestBytesOverhead: 0,
					FeeTokenAmount:    "500000.",
					ExtraArgs:         []byte{},
				},
				{
					Issuer:            addresses.routerIssuer,
					DestGasLimit:      0,
					DestBytesOverhead: 0,
					FeeTokenAmount:    "500000.",
					ExtraArgs:         []byte{},
				},
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

	var indexerMonitor *ccv.IndexerMonitor
	indexerClient, err := lib.Indexer()
	require.NoError(t, err)
	indexerMonitor, err = ccv.NewIndexerMonitor(
		zerolog.Ctx(ctx).With().Str("component", "indexer-client").Logger(),
		indexerClient)
	require.NoError(t, err)
	require.NotNil(t, indexerMonitor)

	aggregatorClients := make(map[string]*ccv.AggregatorClient)
	for qualifier := range in.AggregatorEndpoints {
		client, err := in.NewAggregatorClientForCommittee(
			zerolog.Ctx(ctx).With().Str("component", fmt.Sprintf("aggregator-client-%s", qualifier)).Logger(),
			qualifier)
		require.NoError(t, err)
		require.NotNil(t, client)
		aggregatorClients[qualifier] = client
		t.Cleanup(func() {
			client.Close()
		})
	}
	defaultAggregatorClient := aggregatorClients[devenvcommon.DefaultCommitteeVerifierQualifier]

	testCtx := e2e.NewTestingContext(t, t.Context(), chains, defaultAggregatorClient, indexerMonitor)
	for _, msg := range messages {
		result, err := testCtx.AssertMessage(msg.MustMessageID(), e2e.AssertMessageOptions{
			TickInterval:            1 * time.Second,
			ExpectedVerifierResults: 1, // just committee verifier
			Timeout:                 tests.WaitTimeout(t),
			AssertVerifierLogs:      false,
			AssertExecutorLogs:      false,
		})
		require.NoError(t, err)
		require.NotNil(t, result.AggregatedResult)
		require.Len(t, result.IndexedVerifications.Results, 1)
	}
}

// relevantAddresses are the addresses required to construct a valid CCIP message from Canton -> EVM.
type relevantAddresses struct {
	cantonOnRamp                 []byte
	cantonExecutorAddress        []byte
	cantonDefaultVerifierAddress []byte
	evmOffRamp                   []byte
	evmReceiver                  []byte
	defaultVerifierIssuer        string
	executorIssuer               string
	routerIssuer                 string
}

// getRelevantAddresses returns the canton and evm addresses required to construct a valid CCIP message from Canton -> EVM.
func getRelevantAddresses(t *testing.T, in *ccv.Cfg, cantonDetails, evmDetails chain_selectors.ChainDetails) relevantAddresses {
	cantonOnRampRef, err := in.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			cantonDetails.ChainSelector,
			datastore.ContractType(onrampoperations.ContractType),
			semver.MustParse(onrampoperations.Deploy.Version()),
			"",
		),
	)
	require.NoError(t, err)
	require.NotEmpty(t, cantonOnRampRef.Address)
	t.Logf("canton on ramp address: %s", cantonOnRampRef.Address)

	cantonRouterRef, err := in.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			cantonDetails.ChainSelector,
			datastore.ContractType(routeroperations.ContractType),
			semver.MustParse(routeroperations.Deploy.Version()),
			"",
		),
	)
	require.NoError(t, err)
	require.NotEmpty(t, cantonRouterRef.Address)
	t.Logf("canton router address: %s", cantonRouterRef.Address)
	routerIssuer := string(hexutil.MustDecode(cantonRouterRef.Address))

	cantonDefaultVerifierRef, err := in.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			cantonDetails.ChainSelector,
			datastore.ContractType(committee_verifier.ResolverType),
			semver.MustParse(committee_verifier.Deploy.Version()),
			devenvcommon.DefaultCommitteeVerifierQualifier,
		),
	)
	require.NoError(t, err)
	require.NotEmpty(t, cantonDefaultVerifierRef.Address)
	defaultVerifierIssuer := string(hexutil.MustDecode(cantonDefaultVerifierRef.Address))
	t.Logf("decoded hex len: %d, string len: %d", len(hexutil.MustDecode(cantonDefaultVerifierRef.Address)), len(defaultVerifierIssuer))
	t.Logf("canton default verifier address: %s, issuer: %s", cantonDefaultVerifierRef.Address, defaultVerifierIssuer)

	cantonExecutorAddress, err := in.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			cantonDetails.ChainSelector,
			datastore.ContractType(executor.ProxyType),
			semver.MustParse(executor.DeployProxy.Version()),
			devenvcommon.DefaultExecutorQualifier,
		),
	)
	require.NoError(t, err)
	require.NotEmpty(t, cantonExecutorAddress.Address)
	t.Logf("canton executor address: %s", cantonExecutorAddress.Address)
	executorIssuer := string(hexutil.MustDecode(cantonExecutorAddress.Address))

	evmOffRampRef, err := in.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			evmDetails.ChainSelector,
			datastore.ContractType(offrampoperations.ContractType),
			semver.MustParse(offrampoperations.Deploy.Version()),
			"",
		),
	)
	require.NoError(t, err)
	require.NotEmpty(t, evmOffRampRef.Address)
	t.Logf("evm off ramp address: %s", evmOffRampRef.Address)

	evmReceiverRef, err := in.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			evmDetails.ChainSelector,
			datastore.ContractType(mock_receiver.ContractType),
			semver.MustParse(mock_receiver.Deploy.Version()),
			devenvcommon.DefaultReceiverQualifier,
		),
	)
	require.NoError(t, err)
	require.NotEmpty(t, evmReceiverRef.Address)
	t.Logf("evm receiver address: %s", evmReceiverRef.Address)

	// Convert refs to bytes
	cantonOnRamp := hexutil.MustDecode(cantonOnRampRef.Address)
	evmOffRamp := hexutil.MustDecode(evmOffRampRef.Address)
	require.Len(t, evmOffRamp, 20) // done onchain, do it here just to catch it early
	evmReceiver := hexutil.MustDecode(evmReceiverRef.Address)
	require.Len(t, evmReceiver, 20) // done onchain, do it here just to catch it early

	return relevantAddresses{
		cantonOnRamp:                 cantonOnRamp,
		cantonExecutorAddress:        hexutil.MustDecode(cantonExecutorAddress.Address),
		cantonDefaultVerifierAddress: hexutil.MustDecode(cantonDefaultVerifierRef.Address),
		evmOffRamp:                   evmOffRamp,
		evmReceiver:                  evmReceiver,
		defaultVerifierIssuer:        defaultVerifierIssuer,
		executorIssuer:               executorIssuer,
		routerIssuer:                 routerIssuer,
	}
}

func newMessage(
	t *testing.T,
	sourceSelector,
	destSelector protocol.ChainSelector,
	seqNr int64,
	cantonOnRamp, evmOffRamp, evmReceiver protocol.UnknownAddress,
	ccvAddresses []protocol.UnknownAddress,
	executorAddress protocol.UnknownAddress,
) protocol.Message {
	// Compute the CCV and executor hash for validation
	ccvAndExecutorHash, err := protocol.ComputeCCVAndExecutorHash(ccvAddresses, executorAddress)
	require.NoError(t, err)

	msg, err := protocol.NewMessage(
		sourceSelector,
		destSelector,
		protocol.SequenceNumber(seqNr),
		cantonOnRamp,
		evmOffRamp,
		1,                  // finality
		200_000,            // execution gas limit
		100_000,            // ccip receive gas limit
		ccvAndExecutorHash, // ccv and executor hash
		protocol.UnknownAddress([]byte("sender address")),
		evmReceiver,
		[]byte{},                      // dest blob, not required for EVM.
		[]byte("message from canton"), // message data, can be anything
		nil,                           // token transfer
	)
	require.NoError(t, err)

	return *msg
}

func mustEncodeMessage(t *testing.T, msg protocol.Message) []byte {
	encoded, err := msg.Encode()
	require.NoError(t, err)
	return encoded
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

// testReceipt represents a receipt for the ccipSend choice.
// Matches the Daml Receipt structure.
type testReceipt struct {
	Issuer            string
	DestGasLimit      int64
	DestBytesOverhead int64
	FeeTokenAmount    string // Numeric 0 as string
	ExtraArgs         []byte
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
	receipts []testReceipt,
) *ledgerv2.SubmitAndWaitResponse {
	verifierBlobElements := make([]*ledgerv2.Value, len(verifierBlobs))
	for i, blob := range verifierBlobs {
		verifierBlobElements[i] = &ledgerv2.Value{
			Sum: &ledgerv2.Value_Text{
				Text: hex.EncodeToString(blob),
			},
		}
	}

	receiptElements := make([]*ledgerv2.Value, len(receipts))
	for i, receipt := range receipts {
		receiptElements[i] = &ledgerv2.Value{
			Sum: &ledgerv2.Value_Record{
				Record: &ledgerv2.Record{
					Fields: []*ledgerv2.RecordField{
						{
							Label: "issuer",
							Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: receipt.Issuer}},
						},
						{
							Label: "destGasLimit",
							Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: receipt.DestGasLimit}},
						},
						{
							Label: "destBytesOverhead",
							Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: receipt.DestBytesOverhead}},
						},
						{
							Label: "feeTokenAmount",
							Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Numeric{Numeric: receipt.FeeTokenAmount}},
						},
						{
							Label: "extraArgs",
							Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: hex.EncodeToString(receipt.ExtraArgs)}},
						},
					},
				},
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
											{
												Label: "receipts",
												Value: &ledgerv2.Value{
													Sum: &ledgerv2.Value_List{
														List: &ledgerv2.List{
															Elements: receiptElements,
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

func newTestSetup(helper *devenvcanton.Helper) *testSetup {
	return &testSetup{
		helper: helper,
	}
}
