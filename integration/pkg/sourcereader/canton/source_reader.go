package canton

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	ledgerv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

const (
	// labels for the CCIPMessageSent template.
	ccipMessageSentCCIPOwnerLabel = "ccipOwner"
	ccipMessageSentSenderLabel    = "sender"
	ccipMessageSentObserversLabel = "observers"
	ccipMessageSentEventLabel     = "event"

	// labels for the CCIPMessageSentEvent template.
	ccipMessageSentEventDestChainSelectorLabel = "destChainSelector"
	ccipMessageSentEventSequenceNumberLabel    = "sequenceNumber"
	ccipMessageSentEventMessageIdLabel         = "messageId"
	ccipMessageSentEventEncodedMessageLabel    = "encodedMessage"
	ccipMessageSentEventVerifierBlobsLabel     = "verifierBlobs"
)

type sourceReader struct {
	stateServiceClient  ledgerv2.StateServiceClient
	updateServiceClient ledgerv2.UpdateServiceClient
	jwt                 string

	// ccipOwnerParty is the party that we expect to be present in the CCIPMessageSent.ccipOwner field.
	ccipOwnerParty string
	// ccipMessageSentTemplateID is the template ID of the CCIPMessageSent contract.
	ccipMessageSentTemplateID *ledgerv2.Identifier
}

func NewSourceReader(
	grpcEndpoint,
	jwt string,
	ccipOwnerParty string,
	ccipMessageSentTemplateID *ledgerv2.Identifier,
	opts ...grpc.DialOption) (chainaccess.SourceReader, error) {
	conn, err := grpc.NewClient(grpcEndpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection to canton node: %w", err)
	}

	return &sourceReader{
		stateServiceClient:        ledgerv2.NewStateServiceClient(conn),
		updateServiceClient:       ledgerv2.NewUpdateServiceClient(conn),
		jwt:                       jwt,
		ccipOwnerParty:            ccipOwnerParty,
		ccipMessageSentTemplateID: ccipMessageSentTemplateID,
	}, nil
}

// FetchMessageSentEvents implements chainaccess.SourceReader.
func (c *sourceReader) FetchMessageSentEvents(ctx context.Context, fromBlock, toBlock *big.Int) ([]protocol.MessageSentEvent, error) {
	// since begin is exclusive we need to subtract 1 from fromBlock
	begin := new(big.Int).Sub(fromBlock, big.NewInt(1))
	// check that begin is not negative
	if begin.Sign() < 0 {
		begin = big.NewInt(0)
	}
	end := toBlock.Int64()
	updates, err := c.updateServiceClient.GetUpdates(c.authCtx(ctx), &ledgerv2.GetUpdatesRequest{
		BeginExclusive: begin.Int64(),
		EndInclusive:   &end,
		UpdateFormat: &ledgerv2.UpdateFormat{
			IncludeTransactions: &ledgerv2.TransactionFormat{
				TransactionShape: ledgerv2.TransactionShape_TRANSACTION_SHAPE_ACS_DELTA,
				EventFormat: &ledgerv2.EventFormat{
					FiltersByParty: map[string]*ledgerv2.Filters{
						c.ccipOwnerParty: {
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
					Verbose: true,
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get updates: %w", err)
	}

	var transactions []*ledgerv2.Transaction
	for {
		update, err := updates.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to get updates: %w", err)
		}
		transactions = append(transactions, update.GetTransaction())
	}

	events, err := c.extractEvents(transactions)
	if err != nil {
		return nil, fmt.Errorf("failed to extract events: %w", err)
	}

	return events, nil
}

func (c *sourceReader) extractEvents(transactions []*ledgerv2.Transaction) ([]protocol.MessageSentEvent, error) {
	var events []protocol.MessageSentEvent
	for _, tx := range transactions {
		if tx == nil {
			continue
		}

		for _, event := range tx.GetEvents() {
			if created := event.GetCreated(); created != nil {
				if !identifiersEqual(created.GetTemplateId(), c.ccipMessageSentTemplateID) {
					continue
				}

				for _, field := range created.GetCreateArguments().GetFields() {
					switch field.GetLabel() {
					case ccipMessageSentSenderLabel:
					case ccipMessageSentObserversLabel:
					case ccipMessageSentCCIPOwnerLabel:
						if field.GetValue().GetParty() != c.ccipOwnerParty {
							continue
						}
					case ccipMessageSentEventLabel:
						if field.GetValue().GetRecord() == nil {
							continue
						}

						messageSentEvent, err := processCCIPMessageSentEvent(field)
						if err != nil {
							return nil, fmt.Errorf("failed to process CCIPMessageSent event: %w", err)
						}

						messageSentEvent.BlockNumber = uint64(tx.GetOffset()) //nolint:gosec // offset is always non-negative
						txHash, err := protocol.NewByteSliceFromHex(tx.GetUpdateId())
						if err != nil {
							return nil, fmt.Errorf("failed to parse tx hash from update ID %s: %w", tx.GetUpdateId(), err)
						}
						messageSentEvent.TxHash = txHash

						events = append(events, *messageSentEvent)
					default:
						return nil, fmt.Errorf("unknown CCIPMessageSent event field, possibly mismatched contract/template? : %s", field.GetLabel())
					}
				}
			}
		}
	}

	return events, nil
}

func processCCIPMessageSentEvent(field *ledgerv2.RecordField) (*protocol.MessageSentEvent, error) {
	messageSentEvent := &protocol.MessageSentEvent{}
	for _, eventField := range field.GetValue().GetRecord().GetFields() {
		switch eventField.GetLabel() {
		case ccipMessageSentEventDestChainSelectorLabel:
		case ccipMessageSentEventSequenceNumberLabel:
		case ccipMessageSentEventMessageIdLabel:
			messageID, err := hex.DecodeString(eventField.GetValue().GetText())
			if err != nil {
				return nil, fmt.Errorf("failed to decode message ID: %w, input: %s", err, eventField.GetValue().GetText())
			}
			copy(messageSentEvent.MessageID[:], messageID)
		case ccipMessageSentEventEncodedMessageLabel:
			encodedMessage, err := hex.DecodeString(eventField.GetValue().GetText())
			if err != nil {
				return nil, fmt.Errorf("failed to decode encoded message: %w, input: %s", err, eventField.GetValue().GetText())
			}
			msg, err := protocol.DecodeMessage(encodedMessage)
			if err != nil {
				return nil, fmt.Errorf("failed to decode message: %w, input: %s", err, eventField.GetValue().GetText())
			}
			messageSentEvent.Message = *msg
		case ccipMessageSentEventVerifierBlobsLabel:
			for _, verifierBlob := range eventField.GetValue().GetList().GetElements() {
				verifierBlobBytes, err := hex.DecodeString(verifierBlob.GetText())
				if err != nil {
					return nil, fmt.Errorf("failed to decode verifier blob: %w, input: %s", err, verifierBlob.GetText())
				}
				messageSentEvent.Receipts = append(messageSentEvent.Receipts, protocol.ReceiptWithBlob{
					Blob: verifierBlobBytes,
					// TODO: figure out the rest of the fields, we need at least the issuer address.
					// Or should that be the ccvOwner party?
				})
			}
		default:
			return nil, fmt.Errorf("unknown event field on CCIPMessageSentEvent, possibly mismatched contract/template? : %s", eventField.GetLabel())
		}
	}

	// event validation like checking that message.ID() == messageId
	// should be done in the verifier itself, but we do it here
	// for defense in depth.
	if messageSentEvent.Message.MustMessageID() != messageSentEvent.MessageID {
		return nil, fmt.Errorf("message ID mismatch, from event: %s, from message: %s", messageSentEvent.MessageID.String(), messageSentEvent.Message.MustMessageID().String())
	}

	return messageSentEvent, nil
}

func identifiersEqual(a, b *ledgerv2.Identifier) bool {
	// handle nil cases
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.GetPackageId() == b.GetPackageId() && a.GetModuleName() == b.GetModuleName() && a.GetEntityName() == b.GetEntityName()
}

// GetBlocksHeaders implements chainaccess.SourceReader.
// The blockNumbers passed in are offset numbers, since that's all we ever return from LatestAndFinalizedBlock.
// So there's no need to do a network call here.
func (c *sourceReader) GetBlocksHeaders(ctx context.Context, blockNumbers []*big.Int) (map[*big.Int]protocol.BlockHeader, error) {
	latest, _, err := c.LatestAndFinalizedBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block: %w", err)
	}
	if latest == nil {
		return nil, fmt.Errorf("latest block is nil")
	}

	headers := make(map[*big.Int]protocol.BlockHeader)
	for _, blockNum := range blockNumbers {
		if blockNum.Uint64() > latest.Number {
			return nil, fmt.Errorf("block number is greater than latest offset: %d > %d", blockNum.Uint64(), latest.Number)
		}

		h := intToBytes32(blockNum.Uint64())
		headers[blockNum] = protocol.BlockHeader{
			Number:     blockNum.Uint64(),
			Hash:       h,
			ParentHash: parentHash(blockNum.Uint64()),
			// TODO: determine if we can get an offset's timestamp.
			// Timestamp: time.Time{},
		}
	}
	return headers, nil
}

// GetRMNCursedSubjects implements chainaccess.SourceReader.
func (c *sourceReader) GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error) {
	panic("unimplemented")
}

// LatestAndFinalizedBlock returns the latest offset of the canton validator we are connected to.
// The latest "block" on Canton is always finalized.
func (c *sourceReader) LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error) {
	end, err := c.stateServiceClient.GetLedgerEnd(c.authCtx(ctx), &ledgerv2.GetLedgerEndRequest{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get ledger end: %w", err)
	}
	offsetUint64 := uint64(end.GetOffset()) //nolint:gosec // offset is always non-negative
	h := intToBytes32(offsetUint64)
	parentHash := parentHash(offsetUint64)
	return &protocol.BlockHeader{
			Number:     offsetUint64,
			Hash:       h,
			ParentHash: parentHash,
			// TODO: determine if we can get an offset's timestamp.
			// Timestamp: time.Time{},
		}, &protocol.BlockHeader{
			Number:     offsetUint64,
			Hash:       h,
			ParentHash: parentHash,
			// TODO: determine if we can get an offset's timestamp.
			// Timestamp: time.Time{},
		}, nil
}

func (c *sourceReader) authCtx(ctx context.Context) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", c.jwt)))
}

func intToBytes32(i uint64) protocol.Bytes32 {
	var b protocol.Bytes32
	binary.BigEndian.PutUint64(b[:], i)
	return b
}

func parentHash(i uint64) protocol.Bytes32 {
	// subtract 1 from i in a checked manner
	// i.e. making sure we don't underflow
	if i == 0 {
		return protocol.Bytes32{}
	}
	return intToBytes32(i - 1)
}

var _ chainaccess.SourceReader = (*sourceReader)(nil)
