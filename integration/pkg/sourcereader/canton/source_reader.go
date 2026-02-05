package canton

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	ledgerv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
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
	ccipMessageSentEventMessageIDLabel         = "messageId"
	ccipMessageSentEventEncodedMessageLabel    = "encodedMessage"
	ccipMessageSentEventVerifierBlobsLabel     = "verifierBlobs"
	ccipMessageSentEventReceiptsLabel          = "receipts"

	// labels for the Receipt template.
	ccipMessageSentEventReceiptIssuerLabel            = "issuer"
	ccipMessageSentEventReceiptDestGasLimitLabel      = "destGasLimit"
	ccipMessageSentEventReceiptDestBytesOverheadLabel = "destBytesOverhead"
	ccipMessageSentEventReceiptFeeTokenAmountLabel    = "feeTokenAmount"
	ccipMessageSentEventReceiptExtraArgsLabel         = "extraArgs"
)

// ReaderConfig is the configuration required to create a canton source reader.
type ReaderConfig struct {
	// CCIPOwnerParty is the party that we expect to be present in the CCIPMessageSent.ccipOwner field.
	// This proves that the ccipOwner is a signatory on the CCIPMessageSent contract(event).
	CCIPOwnerParty string `toml:"ccip_owner_party"`
	// CCIPMessageSentTemplateID is the template ID of the CCIPMessageSent contract.
	// Formatted as packageId:moduleName:entityName
	CCIPMessageSentTemplateID string `toml:"ccip_message_sent_template_id"`
	// Authority is the authority to use for the gRPC connection.
	// Connecting to the gRPC API via nginx usually requires this to be set.
	Authority string `toml:"authority"`
}

// GetTemplateID returns a ledgerv2.Identifier from the CCIPMessageSentTemplateID.
// It expects the format to be packageId:moduleName:entityName.
func (c *ReaderConfig) GetTemplateID() (*ledgerv2.Identifier, error) {
	parts := strings.Split(c.CCIPMessageSentTemplateID, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid template ID format, expected packageId:moduleName:entityName, got: %s", c.CCIPMessageSentTemplateID)
	}
	return &ledgerv2.Identifier{
		PackageId:  parts[0],
		ModuleName: parts[1],
		EntityName: parts[2],
	}, nil
}

type sourceReader struct {
	lggr                logger.Logger
	stateServiceClient  ledgerv2.StateServiceClient
	updateServiceClient ledgerv2.UpdateServiceClient
	jwt                 string

	config ReaderConfig
}

func NewSourceReader(
	lggr logger.Logger,
	grpcEndpoint,
	jwt string,
	config ReaderConfig,
	opts ...grpc.DialOption,
) (chainaccess.SourceReader, error) {
	lggr.Infow("creating gRPC connection to canton node", "grpcEndpoint", grpcEndpoint, "config", config)

	if config.Authority != "" {
		opts = append(opts, grpc.WithAuthority(config.Authority))
	}

	conn, err := grpc.NewClient(grpcEndpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection to canton node: %w", err)
	}

	return &sourceReader{
		lggr:                lggr,
		stateServiceClient:  ledgerv2.NewStateServiceClient(conn),
		updateServiceClient: ledgerv2.NewUpdateServiceClient(conn),
		jwt:                 jwt,
		config:              config,
	}, nil
}

// FetchMessageSentEvents implements chainaccess.SourceReader.
func (c *sourceReader) FetchMessageSentEvents(ctx context.Context, fromBlock, toBlock *big.Int) ([]protocol.MessageSentEvent, error) {
	templateID, err := c.config.GetTemplateID()
	if err != nil {
		return nil, fmt.Errorf("failed to get template ID: %w", err)
	}

	// since begin is exclusive we need to subtract 1 from fromBlock
	begin := new(big.Int).Sub(fromBlock, big.NewInt(1))
	// check that begin is not negative
	if begin.Sign() < 0 {
		begin = big.NewInt(0)
	}

	var end *int64
	if toBlock != nil {
		e := toBlock.Int64()
		end = &e
	} else {
		// If toBlock is nil, we need to get the latest ledger end to avoid streaming indefinitely
		// and to ensure we return a slice as expected by the interface.
		ledgerEnd, err := c.stateServiceClient.GetLedgerEnd(c.authCtx(ctx), &ledgerv2.GetLedgerEndRequest{})
		if err != nil {
			return nil, fmt.Errorf("failed to get ledger end for open-ended query: %w", err)
		}
		e := ledgerEnd.GetOffset()
		end = &e
	}

	updates, err := c.updateServiceClient.GetUpdates(c.authCtx(ctx), &ledgerv2.GetUpdatesRequest{
		BeginExclusive: begin.Int64(),
		EndInclusive:   end,
		UpdateFormat: &ledgerv2.UpdateFormat{
			IncludeTransactions: &ledgerv2.TransactionFormat{
				TransactionShape: ledgerv2.TransactionShape_TRANSACTION_SHAPE_ACS_DELTA,
				EventFormat: &ledgerv2.EventFormat{
					FiltersByParty: map[string]*ledgerv2.Filters{
						c.config.CCIPOwnerParty: {
							Cumulative: []*ledgerv2.CumulativeFilter{
								{
									IdentifierFilter: &ledgerv2.CumulativeFilter_TemplateFilter{
										TemplateFilter: &ledgerv2.TemplateFilter{
											TemplateId:              templateID,
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

	events, err := extractEvents(transactions, c.config.CCIPOwnerParty, templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to extract events: %w", err)
	}

	return events, nil
}

func extractEvents(transactions []*ledgerv2.Transaction, ccipOwnerParty string, ccipMessageSentTemplateID *ledgerv2.Identifier) ([]protocol.MessageSentEvent, error) {
	var events []protocol.MessageSentEvent
	for _, tx := range transactions {
		if tx == nil {
			continue
		}

		for _, event := range tx.GetEvents() {
			created := event.GetCreated()
			if created == nil {
				continue
			}
			messageSentEvent, err := processCreatedEvent(tx, created, ccipOwnerParty, ccipMessageSentTemplateID)
			if err != nil {
				// TODO: should we just "continue" here, in the event of a maliciously crafted message/receipts?
				return nil, err
			}
			if messageSentEvent != nil {
				events = append(events, *messageSentEvent)
			}
		}
	}

	return events, nil
}

func processCreatedEvent(
	tx *ledgerv2.Transaction,
	created *ledgerv2.CreatedEvent,
	expectedCCIPOwnerParty string,
	ccipMessageSentTemplateID *ledgerv2.Identifier,
) (*protocol.MessageSentEvent, error) {
	if !identifiersClose(created.GetTemplateId(), ccipMessageSentTemplateID) {
		return nil, nil
	}

	var eventRecordField *ledgerv2.RecordField
	var ccipOwnerParty string

	for _, field := range created.GetCreateArguments().GetFields() {
		switch field.GetLabel() {
		case ccipMessageSentSenderLabel, ccipMessageSentObserversLabel:
			// known fields, ignore
		case ccipMessageSentCCIPOwnerLabel:
			ccipOwnerParty = field.GetValue().GetParty()
		case ccipMessageSentEventLabel:
			eventRecordField = field
		default:
			return nil, fmt.Errorf("unknown CCIPMessageSent event field, possibly mismatched contract/template? : %s", field.GetLabel())
		}
	}

	if ccipOwnerParty != expectedCCIPOwnerParty {
		return nil, nil
	}

	if eventRecordField == nil || eventRecordField.GetValue().GetRecord() == nil {
		return nil, nil
	}

	messageSentEvent, err := processCCIPMessageSentEvent(eventRecordField)
	if err != nil {
		return nil, fmt.Errorf("failed to process CCIPMessageSent event: %w", err)
	}

	messageSentEvent.BlockNumber = uint64(tx.GetOffset()) //nolint:gosec // offset is always non-negative
	txHash, err := protocol.NewByteSliceFromHex(tx.GetUpdateId())
	if err != nil {
		return nil, fmt.Errorf("failed to parse tx hash from update ID %s: %w", tx.GetUpdateId(), err)
	}
	messageSentEvent.TxHash = txHash

	return messageSentEvent, nil
}

func processCCIPMessageSentEvent(field *ledgerv2.RecordField) (*protocol.MessageSentEvent, error) {
	messageSentEvent := &protocol.MessageSentEvent{}
	var verifierBlobs [][]byte
	for _, eventField := range field.GetValue().GetRecord().GetFields() {
		switch eventField.GetLabel() {
		case ccipMessageSentEventDestChainSelectorLabel:
		case ccipMessageSentEventSequenceNumberLabel:
		case ccipMessageSentEventMessageIDLabel:
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
				verifierBlobs = append(verifierBlobs, verifierBlobBytes)
			}
		case ccipMessageSentEventReceiptsLabel:
			protoReceipts, err := processReceipts(eventField)
			if err != nil {
				return nil, fmt.Errorf("failed to process receipts: %w", err)
			}
			messageSentEvent.Receipts = append(messageSentEvent.Receipts, protoReceipts...)
		default:
			return nil, fmt.Errorf("unknown event field on CCIPMessageSentEvent, possibly mismatched contract/template? : %s", eventField.GetLabel())
		}
	}

	// There are more receipts than verifierBlobs.
	// https://github.com/smartcontractkit/chainlink-ccip/blob/f47d23c550cefae31f13ee7368b747018c5035f4/chains/evm/contracts/onRamp/OnRamp.sol#L129-L132
	if len(messageSentEvent.Receipts) < len(verifierBlobs) {
		return nil, fmt.Errorf(
			"expected more receipts than verifier blobs, got %d receipts and %d verifier blobs",
			len(messageSentEvent.Receipts), len(verifierBlobs),
		)
	}

	// populate the receipts w/ the verifier blobs
	// Note: we only populate the blobs for the receipts that have a corresponding verifier blob.
	// The remaining receipts are the executor and network fee receipts.
	for i, blob := range verifierBlobs {
		messageSentEvent.Receipts[i].Blob = blob
	}

	// event validation like checking that message.ID() == messageId
	// should be done in the verifier itself, but we do it here
	// for defense in depth.
	if messageSentEvent.Message.MustMessageID() != messageSentEvent.MessageID {
		return nil, fmt.Errorf("message ID mismatch, from event: %s, from message: %s", messageSentEvent.MessageID.String(), messageSentEvent.Message.MustMessageID().String())
	}

	// Validate ccvAndExecutorHash
	if err := protocol.ValidateCCVAndExecutorHash(messageSentEvent.Message, messageSentEvent.Receipts); err != nil {
		return nil, fmt.Errorf("ccvAndExecutorHash validation failed: %w", err)
	}

	return messageSentEvent, nil
}

// processReceipts processes the receipts from the CCIPMessageSentEvent.
// The expected receipt record field structure is:
/*
data Receipt = Receipt
    with
        issuer : Text              -- CCV ID (e.g., "49ff34ed@party"), pool ID, or "network"
        destGasLimit : Int         -- Gas allocated for dest chain execution
        destBytesOverhead : Int    -- Data availability overhead in bytes
        feeTokenAmount : Numeric 0 -- Fee amount in fee token units
        extraArgs : BytesHex       -- Entity-specific arguments
    deriving (Eq, Show)
*/
func processReceipts(receiptsField *ledgerv2.RecordField) ([]protocol.ReceiptWithBlob, error) {
	elems := receiptsField.GetValue().GetList().GetElements()
	protoReceipts := make([]protocol.ReceiptWithBlob, 0, len(elems))
	for _, receipt := range elems {
		var protoReceipt protocol.ReceiptWithBlob
		for _, field := range receipt.GetRecord().GetFields() {
			switch field.GetLabel() {
			case ccipMessageSentEventReceiptIssuerLabel:
				// issuer is emitted as Text, and its not a hex string.
				// however, in order to make it fit into a protocol.UnknownAddress,
				// we will interpret the string itself as bytes.
				// Note: assume the Text is valid UTF-8.
				decoded, err := protocol.NewUnknownAddressFromHex(field.GetValue().GetText())
				if err != nil {
					return nil, fmt.Errorf("failed to decode issuer: %w, input: %s", err, field.GetValue().GetText())
				}
				protoReceipt.Issuer = decoded
			case ccipMessageSentEventReceiptDestGasLimitLabel:
				protoReceipt.DestGasLimit = uint64(field.GetValue().GetInt64()) //nolint:gosec // int64 is always non-negative
			case ccipMessageSentEventReceiptDestBytesOverheadLabel:
				protoReceipt.DestBytesOverhead = uint32(field.GetValue().GetInt64()) //nolint:gosec // int64 is always non-negative
			case ccipMessageSentEventReceiptFeeTokenAmountLabel:
				// Numerics end in a decimal point, so we have to use big.Float to parse it and then convert to big.Int.
				feeTokenAmountFloat, ok := new(big.Float).SetString(field.GetValue().GetNumeric())
				if !ok {
					return nil, fmt.Errorf("failed to parse fee token amount numeric, input: %s", field.GetValue().GetNumeric())
				}
				feeTokenAmount, _ := feeTokenAmountFloat.Int(nil)
				protoReceipt.FeeTokenAmount = feeTokenAmount
			case ccipMessageSentEventReceiptExtraArgsLabel:
				extraArgs, err := hex.DecodeString(field.GetValue().GetText())
				if err != nil {
					return nil, fmt.Errorf("failed to decode extra args: %w, input: %s", err, field.GetValue().GetText())
				}
				protoReceipt.ExtraArgs = extraArgs
			default:
				return nil, fmt.Errorf("unknown receipt field: %s", field.GetLabel())
			}
		}
		protoReceipts = append(protoReceipts, protoReceipt)
	}

	return protoReceipts, nil
}

func identifiersClose(a, b *ledgerv2.Identifier) bool {
	// handle nil cases
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	// Note: we don't check package ID because what is returned from the server is not the package name
	// but the package hex ID. Since this hex ID may change frequently, we don't want to rely on it.
	return a.GetModuleName() == b.GetModuleName() && a.GetEntityName() == b.GetEntityName()
}

// GetBlocksHeaders implements chainaccess.SourceReader.
// The blockNumbers passed in are offset numbers, since that's all we ever return from LatestAndFinalizedBlock.
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
	// TODO: implement this.
	return nil, nil
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
