package canton

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"testing"

	ledgerv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestSourceReader_LatestAndFinalizedBlock(t *testing.T) {
	t.Run("returns latest and finalized headers", func(t *testing.T) {
		ctx := context.Background()
		jwt := "token"
		offset := int64(42)

		stateClient := mocks.NewMockStateServiceClient(t)
		stateClient.EXPECT().GetLedgerEnd(
			mock.MatchedBy(func(ctx context.Context) bool {
				md, ok := metadata.FromOutgoingContext(ctx)
				if !ok {
					return false
				}
				values := md.Get("authorization")
				return len(values) == 1 && values[0] == "Bearer "+jwt
			}),
			mock.Anything,
		).Return(&ledgerv2.GetLedgerEndResponse{Offset: offset}, nil)

		reader := &sourceReader{
			stateServiceClient: stateClient,
			jwt:                jwt,
		}

		latest, finalized, err := reader.LatestAndFinalizedBlock(ctx)
		require.NoError(t, err)
		require.NotNil(t, latest)
		require.NotNil(t, finalized)
		require.Equal(t, uint64(offset), latest.Number)
		require.Equal(t, intToBytes32(uint64(offset)), latest.Hash)
		require.Equal(t, parentHash(uint64(offset)), latest.ParentHash)
		require.Equal(t, *latest, *finalized)
	})

	t.Run("surfaces ledger end error", func(t *testing.T) {
		ctx := context.Background()
		stateClient := mocks.NewMockStateServiceClient(t)
		expectedErr := errors.New("boom")

		stateClient.EXPECT().GetLedgerEnd(
			mock.Anything,
			mock.Anything,
		).Return((*ledgerv2.GetLedgerEndResponse)(nil), expectedErr)

		reader := &sourceReader{
			stateServiceClient: stateClient,
			jwt:                "token",
		}

		latest, finalized, err := reader.LatestAndFinalizedBlock(ctx)
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to get ledger end")
		require.Nil(t, latest)
		require.Nil(t, finalized)
	})
}

func TestSourceReader_GetBlocksHeaders(t *testing.T) {
	t.Run("builds headers for requested blocks", func(t *testing.T) {
		ctx := context.Background()
		stateClient := mocks.NewMockStateServiceClient(t)

		stateClient.EXPECT().GetLedgerEnd(
			mock.Anything,
			mock.Anything,
		).Return(&ledgerv2.GetLedgerEndResponse{Offset: 10}, nil)

		reader := &sourceReader{
			stateServiceClient: stateClient,
			jwt:                "token",
		}

		blockZero := big.NewInt(0)
		blockFive := big.NewInt(5)
		headers, err := reader.GetBlocksHeaders(ctx, []*big.Int{blockZero, blockFive})
		require.NoError(t, err)
		require.Len(t, headers, 2)
		require.Equal(t, uint64(0), headers[blockZero].Number)
		require.Equal(t, protocol.Bytes32{}, headers[blockZero].ParentHash)
		require.Equal(t, intToBytes32(0), headers[blockZero].Hash)
		require.Equal(t, uint64(5), headers[blockFive].Number)
		require.Equal(t, intToBytes32(4), headers[blockFive].ParentHash)
		require.Equal(t, intToBytes32(5), headers[blockFive].Hash)
	})

	t.Run("errors when block exceeds latest offset", func(t *testing.T) {
		ctx := context.Background()
		stateClient := mocks.NewMockStateServiceClient(t)

		stateClient.EXPECT().GetLedgerEnd(
			mock.Anything,
			mock.Anything,
		).Return(&ledgerv2.GetLedgerEndResponse{Offset: 3}, nil)

		reader := &sourceReader{
			stateServiceClient: stateClient,
			jwt:                "token",
		}

		_, err := reader.GetBlocksHeaders(ctx, []*big.Int{big.NewInt(4)})
		require.Error(t, err)
		require.ErrorContains(t, err, "block number is greater than latest offset")
	})
}

func TestSourceReader_FetchMessageSentEvents(t *testing.T) {
	ccipOwner := "owner-party"
	templateID := &ledgerv2.Identifier{
		PackageId:  "pkg",
		ModuleName: "CCIP",
		EntityName: "CCIPMessageSent",
	}
	templateIDStr := fmt.Sprintf("%s:%s:%s", templateID.PackageId, templateID.ModuleName, templateID.EntityName)

	t.Run("ignores event when ccipOwner does not match", func(t *testing.T) {
		ctx := context.Background()

		msg, err := protocol.NewMessage(
			protocol.ChainSelector(1),
			protocol.ChainSelector(2),
			protocol.SequenceNumber(7),
			protocol.UnknownAddress{0x01},
			protocol.UnknownAddress{0x02},
			1,
			100,
			200,
			protocol.Bytes32{},
			protocol.UnknownAddress{0x03},
			protocol.UnknownAddress{0x04},
			[]byte{0xAA},
			[]byte{0xBB},
			nil,
		)
		require.NoError(t, err)

		encodedMsg, err := msg.Encode()
		require.NoError(t, err)
		msgID := msg.MustMessageID()
		msgIDHex := hex.EncodeToString(msgID[:])
		encodedMsgHex := hex.EncodeToString(encodedMsg)

		created := &ledgerv2.CreatedEvent{
			TemplateId: templateID,
			CreateArguments: &ledgerv2.Record{
				Fields: []*ledgerv2.RecordField{
					{
						Label: ccipMessageSentCCIPOwnerLabel,
						Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Party{Party: "wrong-owner"}}, // wrong owner, should not get processed
					},
					{
						Label: ccipMessageSentEventLabel,
						Value: &ledgerv2.Value{
							Sum: &ledgerv2.Value_Record{
								Record: &ledgerv2.Record{
									Fields: []*ledgerv2.RecordField{
										{
											Label: ccipMessageSentEventDestChainSelectorLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: 2}},
										},
										{
											Label: ccipMessageSentEventSequenceNumberLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: 7}},
										},
										{
											Label: ccipMessageSentEventMessageIDLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: msgIDHex}},
										},
										{
											Label: ccipMessageSentEventEncodedMessageLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: encodedMsgHex}},
										},
										{
											Label: ccipMessageSentEventVerifierBlobsLabel,
											Value: &ledgerv2.Value{
												Sum: &ledgerv2.Value_List{
													List: &ledgerv2.List{Elements: []*ledgerv2.Value{}},
												},
											},
										},
										{
											Label: ccipMessageSentEventReceiptsLabel,
											Value: &ledgerv2.Value{
												Sum: &ledgerv2.Value_List{
													List: &ledgerv2.List{Elements: []*ledgerv2.Value{}},
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
		}

		tx := &ledgerv2.Transaction{
			UpdateId: "0xdeadbeef",
			Offset:   10,
			Events: []*ledgerv2.Event{
				{Event: &ledgerv2.Event_Created{Created: created}},
			},
		}

		stream := &fakeUpdateStream{
			ctx: ctx,
			responses: []*ledgerv2.GetUpdatesResponse{
				{Update: &ledgerv2.GetUpdatesResponse_Transaction{Transaction: tx}},
			},
		}

		updateClient := mocks.NewMockUpdateServiceClient(t)
		updateClient.EXPECT().GetUpdates(
			mock.Anything,
			mock.Anything,
		).Return(stream, nil)

		reader := &sourceReader{
			updateServiceClient: updateClient,
			jwt:                 "token",
			config: ReaderConfig{
				CCIPOwnerParty:            ccipOwner,
				CCIPMessageSentTemplateID: templateIDStr,
			},
		}

		events, err := reader.FetchMessageSentEvents(ctx, big.NewInt(1), big.NewInt(5))
		require.NoError(t, err)
		require.Empty(t, events)
	})

	t.Run("returns error when stream recv fails", func(t *testing.T) {
		ctx := context.Background()
		updateClient := mocks.NewMockUpdateServiceClient(t)
		stream := &fakeUpdateStream{
			ctx: ctx,
			err: errors.New("recv failed"),
		}

		updateClient.EXPECT().GetUpdates(
			mock.Anything,
			mock.Anything,
		).Return(stream, nil)

		reader := &sourceReader{
			updateServiceClient: updateClient,
			jwt:                 "token",
			config: ReaderConfig{
				CCIPOwnerParty:            ccipOwner,
				CCIPMessageSentTemplateID: templateIDStr,
			},
		}

		_, err := reader.FetchMessageSentEvents(ctx, big.NewInt(1), big.NewInt(2))
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to get updates")
	})

	t.Run("uses zero begin exclusive when fromBlock is zero", func(t *testing.T) {
		ctx := context.Background()
		updateClient := mocks.NewMockUpdateServiceClient(t)
		stream := &fakeUpdateStream{ctx: ctx}

		updateClient.EXPECT().GetUpdates(
			mock.Anything,
			mock.MatchedBy(func(req *ledgerv2.GetUpdatesRequest) bool {
				if req.GetBeginExclusive() != 0 {
					return false
				}
				if req.EndInclusive == nil || *req.EndInclusive != 2 {
					return false
				}
				return true
			}),
		).Return(stream, nil)

		reader := &sourceReader{
			updateServiceClient: updateClient,
			jwt:                 "token",
			config: ReaderConfig{
				CCIPOwnerParty:            ccipOwner,
				CCIPMessageSentTemplateID: templateIDStr,
			},
		}

		events, err := reader.FetchMessageSentEvents(ctx, big.NewInt(0), big.NewInt(2))
		require.NoError(t, err)
		require.Empty(t, events)
	})

	t.Run("parses events with verifier blobs and receipts", func(t *testing.T) {
		ctx := context.Background()

		verifierBlobHex := "deadbeef"
		extraArgsHex := "cafebabe"

		ccvIssuer := protocol.Keccak256([]byte("issuer1"))
		execIssuer := protocol.Keccak256([]byte("executor"))
		networkIssuer := protocol.Keccak256([]byte("network"))

		receipts := &ledgerv2.List{Elements: []*ledgerv2.Value{
			// First receipt - has corresponding verifier blob
			{Sum: &ledgerv2.Value_Record{Record: &ledgerv2.Record{
				Fields: []*ledgerv2.RecordField{
					{Label: ccipMessageSentEventReceiptIssuerLabel, Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: hex.EncodeToString(ccvIssuer[:])}}},
					{Label: ccipMessageSentEventReceiptDestGasLimitLabel, Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: 100000}}},
					{Label: ccipMessageSentEventReceiptDestBytesOverheadLabel, Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: 500}}},
					{Label: ccipMessageSentEventReceiptFeeTokenAmountLabel, Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Numeric{Numeric: "1000000."}}},
					{Label: ccipMessageSentEventReceiptExtraArgsLabel, Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: extraArgsHex}}},
				},
			}}},
			// Second receipt - executor receipt
			{Sum: &ledgerv2.Value_Record{Record: &ledgerv2.Record{
				Fields: []*ledgerv2.RecordField{
					{Label: ccipMessageSentEventReceiptIssuerLabel, Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: hex.EncodeToString(execIssuer[:])}}},
					{Label: ccipMessageSentEventReceiptDestGasLimitLabel, Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: 0}}},
					{Label: ccipMessageSentEventReceiptDestBytesOverheadLabel, Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: 0}}},
					{Label: ccipMessageSentEventReceiptFeeTokenAmountLabel, Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Numeric{Numeric: "500000."}}},
					{Label: ccipMessageSentEventReceiptExtraArgsLabel, Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: ""}}},
				},
			}}},
			// Second receipt - no verifier blob (e.g., network fee receipt)
			{Sum: &ledgerv2.Value_Record{Record: &ledgerv2.Record{
				Fields: []*ledgerv2.RecordField{
					{Label: ccipMessageSentEventReceiptIssuerLabel, Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: hex.EncodeToString(networkIssuer[:])}}},
					{Label: ccipMessageSentEventReceiptDestGasLimitLabel, Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: 0}}},
					{Label: ccipMessageSentEventReceiptDestBytesOverheadLabel, Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: 0}}},
					{Label: ccipMessageSentEventReceiptFeeTokenAmountLabel, Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Numeric{Numeric: "500000."}}},
					{Label: ccipMessageSentEventReceiptExtraArgsLabel, Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: ""}}},
				},
			}}},
		}}
		receiptsWithBlobs, err := processReceipts(&ledgerv2.RecordField{Value: &ledgerv2.Value{Sum: &ledgerv2.Value_List{List: receipts}}})
		require.NoError(t, err)
		require.Len(t, receiptsWithBlobs, 3) // 1 verifier blob, 1 executor receipt, 1 network fee receipt

		structure, err := protocol.ParseReceiptStructure(receiptsWithBlobs, 1, 0)
		require.NoError(t, err)

		ccvAndExecutorHash, err := protocol.ComputeCCVAndExecutorHash(structure.CCVAddresses, structure.ExecutorAddress)
		require.NoError(t, err)

		msg, err := protocol.NewMessage(
			protocol.ChainSelector(1),
			protocol.ChainSelector(2),
			protocol.SequenceNumber(7),
			protocol.UnknownAddress{0x01},
			protocol.UnknownAddress{0x02},
			1,
			100,
			200,
			ccvAndExecutorHash,
			protocol.UnknownAddress{0x03},
			protocol.UnknownAddress{0x04},
			[]byte{0xAA},
			[]byte{0xBB},
			nil,
		)
		require.NoError(t, err)

		encodedMsg, err := msg.Encode()
		require.NoError(t, err)
		msgID := msg.MustMessageID()
		msgIDHex := hex.EncodeToString(msgID[:])
		encodedMsgHex := hex.EncodeToString(encodedMsg)

		created := &ledgerv2.CreatedEvent{
			TemplateId: templateID,
			CreateArguments: &ledgerv2.Record{
				Fields: []*ledgerv2.RecordField{
					{
						Label: ccipMessageSentCCIPOwnerLabel,
						Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Party{Party: ccipOwner}},
					},
					{
						Label: ccipMessageSentEventLabel,
						Value: &ledgerv2.Value{
							Sum: &ledgerv2.Value_Record{
								Record: &ledgerv2.Record{
									Fields: []*ledgerv2.RecordField{
										{
											Label: ccipMessageSentEventDestChainSelectorLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: 2}},
										},
										{
											Label: ccipMessageSentEventSequenceNumberLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: 7}},
										},
										{
											Label: ccipMessageSentEventMessageIDLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: msgIDHex}},
										},
										{
											Label: ccipMessageSentEventEncodedMessageLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: encodedMsgHex}},
										},
										{
											Label: ccipMessageSentEventVerifierBlobsLabel,
											Value: &ledgerv2.Value{
												Sum: &ledgerv2.Value_List{
													List: &ledgerv2.List{Elements: []*ledgerv2.Value{
														{Sum: &ledgerv2.Value_Text{Text: verifierBlobHex}},
													}},
												},
											},
										},
										{
											Label: ccipMessageSentEventReceiptsLabel,
											Value: &ledgerv2.Value{
												Sum: &ledgerv2.Value_List{
													List: receipts,
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
		}

		tx := &ledgerv2.Transaction{
			UpdateId: "0xdeadbeef",
			Offset:   10,
			Events: []*ledgerv2.Event{
				{Event: &ledgerv2.Event_Created{Created: created}},
			},
		}

		stream := &fakeUpdateStream{
			ctx: ctx,
			responses: []*ledgerv2.GetUpdatesResponse{
				{Update: &ledgerv2.GetUpdatesResponse_Transaction{Transaction: tx}},
			},
		}

		updateClient := mocks.NewMockUpdateServiceClient(t)
		updateClient.EXPECT().GetUpdates(mock.Anything, mock.Anything).Return(stream, nil)

		reader := &sourceReader{
			updateServiceClient: updateClient,
			jwt:                 "token",
			config: ReaderConfig{
				CCIPOwnerParty:            ccipOwner,
				CCIPMessageSentTemplateID: templateIDStr,
			},
		}

		events, err := reader.FetchMessageSentEvents(ctx, big.NewInt(1), big.NewInt(5))
		require.NoError(t, err)
		require.Len(t, events, 1)
		require.Equal(t, msg.MustMessageID(), events[0].MessageID)

		// Assert receipts were properly parsed
		require.Len(t, events[0].Receipts, 3)

		// First receipt - should have verifier blob populated
		receipt1 := events[0].Receipts[0]
		require.Equal(t, protocol.UnknownAddress(ccvIssuer[:]), receipt1.Issuer)
		require.Equal(t, uint64(100000), receipt1.DestGasLimit)
		require.Equal(t, uint32(500), receipt1.DestBytesOverhead)
		require.Equal(t, big.NewInt(1000000), receipt1.FeeTokenAmount)
		expectedExtraArgs, _ := hex.DecodeString(extraArgsHex)
		require.Equal(t, protocol.ByteSlice(expectedExtraArgs), receipt1.ExtraArgs)
		expectedBlob, _ := hex.DecodeString(verifierBlobHex)
		require.Equal(t, protocol.ByteSlice(expectedBlob), receipt1.Blob)

		// Second receipt - no verifier blob (executor fee receipt)
		receipt2 := events[0].Receipts[1]
		require.Equal(t, protocol.UnknownAddress(execIssuer[:]), receipt2.Issuer)
		require.Equal(t, uint64(0), receipt2.DestGasLimit)
		require.Equal(t, uint32(0), receipt2.DestBytesOverhead)
		require.Equal(t, big.NewInt(500000), receipt2.FeeTokenAmount)
		require.Empty(t, receipt2.ExtraArgs)
		require.Nil(t, receipt2.Blob) // No corresponding verifier blob

		// Third receipt - no verifier blob (network fee receipt)
		receipt3 := events[0].Receipts[2]
		require.Equal(t, protocol.UnknownAddress(networkIssuer[:]), receipt3.Issuer)
		require.Equal(t, uint64(0), receipt3.DestGasLimit)
		require.Equal(t, uint32(0), receipt3.DestBytesOverhead)
		require.Equal(t, big.NewInt(500000), receipt3.FeeTokenAmount)
		require.Empty(t, receipt3.ExtraArgs)
		require.Nil(t, receipt3.Blob) // No corresponding verifier blob
	})

	t.Run("returns error when receipts fewer than verifier blobs", func(t *testing.T) {
		ctx := context.Background()

		msg, err := protocol.NewMessage(
			protocol.ChainSelector(1),
			protocol.ChainSelector(2),
			protocol.SequenceNumber(7),
			protocol.UnknownAddress{0x01},
			protocol.UnknownAddress{0x02},
			1,
			100,
			200,
			protocol.Bytes32{},
			protocol.UnknownAddress{0x03},
			protocol.UnknownAddress{0x04},
			[]byte{0xAA},
			[]byte{0xBB},
			nil,
		)
		require.NoError(t, err)

		encodedMsg, err := msg.Encode()
		require.NoError(t, err)
		msgID := msg.MustMessageID()
		msgIDHex := hex.EncodeToString(msgID[:])
		encodedMsgHex := hex.EncodeToString(encodedMsg)

		// Two verifier blobs but zero receipts - should fail
		created := &ledgerv2.CreatedEvent{
			TemplateId: templateID,
			CreateArguments: &ledgerv2.Record{
				Fields: []*ledgerv2.RecordField{
					{
						Label: ccipMessageSentCCIPOwnerLabel,
						Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Party{Party: ccipOwner}},
					},
					{
						Label: ccipMessageSentEventLabel,
						Value: &ledgerv2.Value{
							Sum: &ledgerv2.Value_Record{
								Record: &ledgerv2.Record{
									Fields: []*ledgerv2.RecordField{
										{
											Label: ccipMessageSentEventDestChainSelectorLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: 2}},
										},
										{
											Label: ccipMessageSentEventSequenceNumberLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: 7}},
										},
										{
											Label: ccipMessageSentEventMessageIDLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: msgIDHex}},
										},
										{
											Label: ccipMessageSentEventEncodedMessageLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: encodedMsgHex}},
										},
										{
											Label: ccipMessageSentEventVerifierBlobsLabel,
											Value: &ledgerv2.Value{
												Sum: &ledgerv2.Value_List{
													List: &ledgerv2.List{Elements: []*ledgerv2.Value{
														{Sum: &ledgerv2.Value_Text{Text: "deadbeef"}},
														{Sum: &ledgerv2.Value_Text{Text: "cafebabe"}},
													}},
												},
											},
										},
										{
											Label: ccipMessageSentEventReceiptsLabel,
											Value: &ledgerv2.Value{
												Sum: &ledgerv2.Value_List{
													List: &ledgerv2.List{Elements: []*ledgerv2.Value{}},
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
		}

		tx := &ledgerv2.Transaction{
			UpdateId: "0xdeadbeef",
			Offset:   10,
			Events: []*ledgerv2.Event{
				{Event: &ledgerv2.Event_Created{Created: created}},
			},
		}

		stream := &fakeUpdateStream{
			ctx: ctx,
			responses: []*ledgerv2.GetUpdatesResponse{
				{Update: &ledgerv2.GetUpdatesResponse_Transaction{Transaction: tx}},
			},
		}

		updateClient := mocks.NewMockUpdateServiceClient(t)
		updateClient.EXPECT().GetUpdates(mock.Anything, mock.Anything).Return(stream, nil)

		reader := &sourceReader{
			updateServiceClient: updateClient,
			jwt:                 "token",
			config: ReaderConfig{
				CCIPOwnerParty:            ccipOwner,
				CCIPMessageSentTemplateID: templateIDStr,
			},
		}

		_, err = reader.FetchMessageSentEvents(ctx, big.NewInt(1), big.NewInt(5))
		require.Error(t, err)
		require.ErrorContains(t, err, "expected more receipts than verifier blobs")
	})

	t.Run("returns error on unknown receipt field", func(t *testing.T) {
		ctx := context.Background()

		msg, err := protocol.NewMessage(
			protocol.ChainSelector(1),
			protocol.ChainSelector(2),
			protocol.SequenceNumber(7),
			protocol.UnknownAddress{0x01},
			protocol.UnknownAddress{0x02},
			1,
			100,
			200,
			protocol.Bytes32{},
			protocol.UnknownAddress{0x03},
			protocol.UnknownAddress{0x04},
			[]byte{0xAA},
			[]byte{0xBB},
			nil,
		)
		require.NoError(t, err)

		encodedMsg, err := msg.Encode()
		require.NoError(t, err)
		msgID := msg.MustMessageID()
		msgIDHex := hex.EncodeToString(msgID[:])
		encodedMsgHex := hex.EncodeToString(encodedMsg)

		created := &ledgerv2.CreatedEvent{
			TemplateId: templateID,
			CreateArguments: &ledgerv2.Record{
				Fields: []*ledgerv2.RecordField{
					{
						Label: ccipMessageSentCCIPOwnerLabel,
						Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Party{Party: ccipOwner}},
					},
					{
						Label: ccipMessageSentEventLabel,
						Value: &ledgerv2.Value{
							Sum: &ledgerv2.Value_Record{
								Record: &ledgerv2.Record{
									Fields: []*ledgerv2.RecordField{
										{
											Label: ccipMessageSentEventDestChainSelectorLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: 2}},
										},
										{
											Label: ccipMessageSentEventSequenceNumberLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Int64{Int64: 7}},
										},
										{
											Label: ccipMessageSentEventMessageIDLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: msgIDHex}},
										},
										{
											Label: ccipMessageSentEventEncodedMessageLabel,
											Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: encodedMsgHex}},
										},
										{
											Label: ccipMessageSentEventVerifierBlobsLabel,
											Value: &ledgerv2.Value{
												Sum: &ledgerv2.Value_List{
													List: &ledgerv2.List{Elements: []*ledgerv2.Value{}},
												},
											},
										},
										{
											Label: ccipMessageSentEventReceiptsLabel,
											Value: &ledgerv2.Value{
												Sum: &ledgerv2.Value_List{
													List: &ledgerv2.List{Elements: []*ledgerv2.Value{
														{Sum: &ledgerv2.Value_Record{Record: &ledgerv2.Record{
															Fields: []*ledgerv2.RecordField{
																{Label: "unknownField", Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: "value"}}},
															},
														}}},
													}},
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
		}

		tx := &ledgerv2.Transaction{
			UpdateId: "0xdeadbeef",
			Offset:   10,
			Events: []*ledgerv2.Event{
				{Event: &ledgerv2.Event_Created{Created: created}},
			},
		}

		stream := &fakeUpdateStream{
			ctx: ctx,
			responses: []*ledgerv2.GetUpdatesResponse{
				{Update: &ledgerv2.GetUpdatesResponse_Transaction{Transaction: tx}},
			},
		}

		updateClient := mocks.NewMockUpdateServiceClient(t)
		updateClient.EXPECT().GetUpdates(mock.Anything, mock.Anything).Return(stream, nil)

		reader := &sourceReader{
			updateServiceClient: updateClient,
			jwt:                 "token",
			config: ReaderConfig{
				CCIPOwnerParty:            ccipOwner,
				CCIPMessageSentTemplateID: templateIDStr,
			},
		}

		_, err = reader.FetchMessageSentEvents(ctx, big.NewInt(1), big.NewInt(5))
		require.Error(t, err)
		require.ErrorContains(t, err, "unknown receipt field")
	})
}

type fakeUpdateStream struct {
	ctx       context.Context
	responses []*ledgerv2.GetUpdatesResponse
	err       error
	idx       int
}

func (s *fakeUpdateStream) Recv() (*ledgerv2.GetUpdatesResponse, error) {
	if s.idx < len(s.responses) {
		resp := s.responses[s.idx]
		s.idx++
		return resp, nil
	}
	if s.err != nil {
		return nil, s.err
	}
	return nil, io.EOF
}

func (s *fakeUpdateStream) Header() (metadata.MD, error) {
	return metadata.MD{}, nil
}

func (s *fakeUpdateStream) Trailer() metadata.MD {
	return metadata.MD{}
}

func (s *fakeUpdateStream) CloseSend() error {
	return nil
}

func (s *fakeUpdateStream) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

func (s *fakeUpdateStream) SendMsg(any) error {
	return nil
}

func (s *fakeUpdateStream) RecvMsg(any) error {
	return nil
}

var _ grpc.ServerStreamingClient[ledgerv2.GetUpdatesResponse] = (*fakeUpdateStream)(nil)
