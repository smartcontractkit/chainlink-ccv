package stellar

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/rpcclient"
	protocolrpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Compile-time check to ensure we satisfy the chainaccess.SourceReader interface.
var _ chainaccess.SourceReader = (*SourceReader)(nil)

// RPCClient defines the interface for Stellar RPC client methods used by SourceReader.
// This interface allows for mocking in unit tests.
type RPCClient interface {
	// GetLatestLedger returns the latest ledger information.
	GetLatestLedger(ctx context.Context) (protocolrpc.GetLatestLedgerResponse, error)
	// GetLedgers returns ledger data for a range of ledgers.
	GetLedgers(ctx context.Context, req protocolrpc.GetLedgersRequest) (protocolrpc.GetLedgersResponse, error)
	// GetEvents returns contract events matching the specified filters.
	GetEvents(ctx context.Context, req protocolrpc.GetEventsRequest) (protocolrpc.GetEventsResponse, error)
}

// Compile-time check to ensure rpcclient.Client satisfies our interface.
var _ RPCClient = (*rpcclient.Client)(nil)

// ReaderConfig is the configuration required to create a Stellar source reader.
type ReaderConfig struct {
	// NetworkPassphrase is the Stellar network passphrase (e.g., "Standalone Network ; February 2017").
	NetworkPassphrase string `toml:"network_passphrase"`
	// OnRampContractID is the contract ID of the Stellar OnRamp contract.
	OnRampContractID string `toml:"onramp_contract_id"`
	// SorobanRPCURL is the URL of the Soroban RPC endpoint.
	SorobanRPCURL string `toml:"soroban_rpc_url"`
}

// TransferEvent represents a decoded Stellar transfer event with signature (address, address, i128).
type TransferEvent struct {
	// From is the source address (strkey-encoded, e.g., G... for accounts, C... for contracts)
	From string
	// To is the destination address (strkey-encoded)
	To string
	// Amount is the transfer amount as i128
	Amount *big.Int
	// Ledger is the ledger sequence number where this event occurred
	Ledger uint32
	// TransactionHash is the transaction hash
	TransactionHash string
}

// SourceReader is the Stellar implementation of chainaccess.SourceReader.
type SourceReader struct {
	client               RPCClient
	ccipOnrampAddress    string
	ccipMessageSentTopic string
	lggr                 logger.Logger
}

// NewSourceReaderWithClient constructs a Stellar source reader with a RPC client.
func NewSourceReaderWithClient(
	client RPCClient,
	ccipOnrampAddress string,
	ccipMessageSentTopic string,
	lggr logger.Logger,
) (*SourceReader, error) {
	if client == nil {
		return nil, fmt.Errorf("rpc client is required")
	}
	if lggr == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if ccipOnrampAddress == "" {
		return nil, fmt.Errorf("ccip onramp address is required")
	}
	if ccipMessageSentTopic == "" {
		return nil, fmt.Errorf("ccip message sent topic is required")
	}

	return &SourceReader{
		client:               client,
		ccipOnrampAddress:    ccipOnrampAddress,
		ccipMessageSentTopic: ccipMessageSentTopic,
		lggr:                 lggr,
	}, nil
}

// FetchMessageSentEvents fetches CCIP MessageSent events from the Stellar OnRamp contract.
func (s *SourceReader) FetchMessageSentEvents(ctx context.Context, fromBlock, toBlock *big.Int) ([]protocol.MessageSentEvent, error) {
	fromSeq := fromBlock.Uint64()
	if fromSeq > math.MaxUint32 {
		return nil, fmt.Errorf("block number exceeds uint32 (ledger seq) range: %d", fromSeq)
	}
	fromLedger := uint32(fromSeq)

	var toLedger uint32
	if toBlock != nil {
		toSeq := toBlock.Uint64()
		if toSeq > math.MaxUint32 {
			return nil, fmt.Errorf("block number exceeds uint32 (ledger seq) range: %d", toSeq)
		}
		toLedger = uint32(toSeq)
	} else {
		latestLedger, err := s.client.GetLatestLedger(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get latest ledger: %w", err)
		}
		toLedger = latestLedger.Sequence
	}

	// Build topic filter for CCIPMessageSent event
	topicScVal, err := symbolScVal(s.ccipMessageSentTopic)
	if err != nil {
		return nil, fmt.Errorf("invalid topic symbol: %w", err)
	}

	// Use wildcard to match events with additional topics
	zeroOrMore := protocolrpc.WildCardZeroOrMore
	events, err := s.client.GetEvents(ctx, protocolrpc.GetEventsRequest{
		StartLedger: fromLedger,
		EndLedger:   toLedger,
		Filters: []protocolrpc.EventFilter{
			{
				EventType:   protocolrpc.EventTypeSet{protocolrpc.EventTypeContract: nil},
				ContractIDs: []string{s.ccipOnrampAddress},
				Topics: []protocolrpc.TopicFilter{
					{
						{ScVal: topicScVal},
						{Wildcard: &zeroOrMore},
					},
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get events: %w", err)
	}

	results := make([]protocol.MessageSentEvent, 0, len(events.Events))
	for _, e := range events.Events {
		// Parse the CCIPMessageSent event
		msgEvent, err := s.decodeCCIPMessageSentEvent(e)
		if err != nil {
			s.lggr.Warnw("Failed to decode CCIPMessageSent event, skipping",
				"error", err,
				"ledger", e.Ledger,
				"txHash", e.TransactionHash,
			)
			continue
		}
		results = append(results, *msgEvent)
	}

	s.lggr.Infow("Fetched CCIPMessageSent events",
		"fromLedger", fromLedger,
		"toLedger", toLedger,
		"count", len(results))

	return results, nil
}

// decodeCCIPMessageSentEvent decodes a CCIPMessageSent event from Stellar.
func (s *SourceReader) decodeCCIPMessageSentEvent(e protocolrpc.EventInfo) (*protocol.MessageSentEvent, error) {
	// Parse the event value which contains the event data as a struct
	var eventVal xdr.ScVal
	if err := xdr.SafeUnmarshalBase64(e.ValueXDR, &eventVal); err != nil {
		return nil, fmt.Errorf("failed to decode event value: %w", err)
	}

	scMap, ok := eventVal.GetMap()
	if !ok || scMap == nil {
		return nil, fmt.Errorf("event value is not a map")
	}

	// Extract fields from the event
	var (
		destChainSelector uint64
		sequenceNumber    uint64
		sender            string
		messageID         [32]byte
		encodedMessage    []byte
	)

	for _, entry := range *scMap {
		key, ok := entry.Key.GetSym()
		if !ok {
			continue
		}

		switch string(key) {
		case "dest_chain_selector":
			u64, ok := entry.Val.GetU64()
			if ok {
				destChainSelector = uint64(u64)
			}
		case "sequence_number":
			u64, ok := entry.Val.GetU64()
			if ok {
				sequenceNumber = uint64(u64)
			}
		case "sender":
			// Encode the ScVal to base64 for address decoding
			valBytes, err := entry.Val.MarshalBinary()
			if err == nil {
				valB64 := base64.StdEncoding.EncodeToString(valBytes)
				addr, addrErr := decodeAddress(valB64)
				if addrErr == nil {
					sender = addr
				}
			}
		case "message_id":
			if bytes, ok := entry.Val.GetBytes(); ok && len(bytes) == 32 {
				copy(messageID[:], bytes)
			}
		case "encoded_message":
			if bytes, ok := entry.Val.GetBytes(); ok {
				encodedMessage = []byte(bytes)
			}
		}
	}

	s.lggr.Infow("Decoded CCIPMessageSent event",
		"destChainSelector", destChainSelector,
		"sequenceNumber", sequenceNumber,
		"messageId", hex.EncodeToString(messageID[:]),
		"ledger", e.Ledger)

	// Build the Message struct from the encoded message or available data
	msg := &protocol.Message{
		Sender:              protocol.UnknownAddress([]byte(sender)),
		SenderLength:        uint8(len(sender)),
		Data:                encodedMessage,
		DataLength:          uint16(len(encodedMessage)),
		Version:             protocol.MessageVersion,
		SequenceNumber:      protocol.SequenceNumber(sequenceNumber),
		DestChainSelector:   protocol.ChainSelector(destChainSelector),
	}

	return &protocol.MessageSentEvent{
		MessageID:   protocol.Bytes32(messageID),
		Message:     *msg,
		BlockNumber: uint64(e.Ledger),
		TxHash:      protocol.ByteSlice([]byte(e.TransactionHash)),
	}, nil
}

// FetchTransferEvents fetches and decodes transfer events with signature (address, address, i128).
// Event structure: topics=[Symbol("transfer"), Address(from), Address(to), ...], value=i128(amount).
func (s *SourceReader) FetchTransferEvents(ctx context.Context, fromBlock, toBlock *big.Int) ([]TransferEvent, error) {
	fromSeq := fromBlock.Uint64()
	if fromSeq > math.MaxUint32 {
		return nil, fmt.Errorf("block number exceeds uint32 (ledger seq) range: %d", fromSeq)
	}
	fromLedger := uint32(fromSeq)

	var toLedger uint32
	if toBlock != nil {
		toSeq := toBlock.Uint64()
		if toSeq > math.MaxUint32 {
			return nil, fmt.Errorf("block number exceeds uint32 (ledger seq) range: %d", toSeq)
		}
		toLedger = uint32(toSeq)
	} else {
		latestLedger, err := s.client.GetLatestLedger(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get latest ledger: %w", err)
		}
		toLedger = latestLedger.Sequence
	}

	topicScVal, err := symbolScVal(s.ccipMessageSentTopic)
	if err != nil {
		return nil, fmt.Errorf("invalid topic symbol: %w", err)
	}

	// Use "**" wildcard to match events with more topics than we're filtering on
	zeroOrMore := protocolrpc.WildCardZeroOrMore
	events, err := s.client.GetEvents(ctx, protocolrpc.GetEventsRequest{
		StartLedger: fromLedger,
		EndLedger:   toLedger,
		Filters: []protocolrpc.EventFilter{
			{
				EventType:   protocolrpc.EventTypeSet{protocolrpc.EventTypeContract: nil},
				ContractIDs: []string{s.ccipOnrampAddress},
				Topics: []protocolrpc.TopicFilter{
					{
						{ScVal: topicScVal},     // Match first topic (event name)
						{Wildcard: &zeroOrMore}, // Match any remaining topics
					},
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get events: %w", err)
	}

	results := make([]TransferEvent, 0, len(events.Events))
	for _, e := range events.Events {
		// Decode transfer event: topics=[Symbol, Address(from), Address(to), ...], value=i128
		transfer, err := decodeTransferEvent(e.TopicXDR, e.ValueXDR)
		if err != nil {
			s.lggr.Warnw("Failed to decode transfer event, skipping",
				"error", err,
				"ledger", e.Ledger,
				"txHash", e.TransactionHash,
			)
			continue
		}

		if e.Ledger < 0 {
			s.lggr.Warnw("Invalid negative ledger number, skipping",
				"ledger", e.Ledger,
				"txHash", e.TransactionHash,
			)
			continue
		}
		transfer.Ledger = uint32(e.Ledger)
		transfer.TransactionHash = e.TransactionHash
		results = append(results, *transfer)
	}
	return results, nil
}

// // RawEvent represents a raw contract event.
// type RawEvent struct {
// 	ContractID      string
// 	Ledger          uint32
// 	TransactionHash string
// 	EventType       string
// 	TopicXDR        []string
// 	ValueXDR        string
// }

// // FetchAllEvents fetches contract events in a ledger range.
// // Filters by contract ID and the configured ccipMessageSentTopic.
// func (s *SourceReader) FetchAllEvents(ctx context.Context, fromBlock, toBlock *big.Int, contractID string) ([]RawEvent, error) {
// 	fromSeq := fromBlock.Uint64()
// 	if fromSeq > math.MaxUint32 {
// 		return nil, fmt.Errorf("block number exceeds uint32 range: %d", fromSeq)
// 	}
// 	fromLedger := uint32(fromSeq)

// 	var toLedger uint32
// 	if toBlock != nil {
// 		toSeq := toBlock.Uint64()
// 		if toSeq > math.MaxUint32 {
// 			return nil, fmt.Errorf("block number exceeds uint32 range: %d", toSeq)
// 		}
// 		toLedger = uint32(toSeq)
// 	} else {
// 		latestLedger, err := s.client.GetLatestLedger(ctx)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to get latest ledger: %w", err)
// 		}
// 		toLedger = latestLedger.Sequence
// 	}

// 	// Build topic filter for ccipMessageSentTopic
// 	topicScVal, err := symbolScVal(s.ccipMessageSentTopic)
// 	if err != nil {
// 		return nil, fmt.Errorf("invalid topic symbol: %w", err)
// 	}

// 	// Use "**" wildcard to match events with more topics than we're filtering on
// 	zeroOrMore := protocolrpc.WildCardZeroOrMore

// 	// Build filter with contract ID and topic
// 	filter := protocolrpc.EventFilter{
// 		EventType: protocolrpc.EventTypeSet{protocolrpc.EventTypeContract: nil},
// 		Topics: []protocolrpc.TopicFilter{
// 			{
// 				{ScVal: topicScVal},     // Match first topic (event name)
// 				{Wildcard: &zeroOrMore}, // Match any remaining topics
// 			},
// 		},
// 	}
// 	if contractID != "" {
// 		filter.ContractIDs = []string{contractID}
// 	}

// 	events, err := s.client.GetEvents(ctx, protocolrpc.GetEventsRequest{
// 		StartLedger: fromLedger,
// 		EndLedger:   toLedger,
// 		Filters:     []protocolrpc.EventFilter{filter},
// 	})
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get events: %w", err)
// 	}

// 	results := make([]RawEvent, 0, len(events.Events))
// 	for _, e := range events.Events {
// 		results = append(results, RawEvent{
// 			ContractID:      e.ContractID,
// 			Ledger:          uint32(e.Ledger),
// 			TransactionHash: e.TransactionHash,
// 			EventType:       e.EventType,
// 			TopicXDR:        e.TopicXDR,
// 			ValueXDR:        e.ValueXDR,
// 		})
// 	}
// 	return results, nil
// }

// // DecodeScVal decodes a base64 XDR ScVal and returns a human-readable string.
// func DecodeScVal(b64 string) (string, error) {
// 	var scVal xdr.ScVal
// 	if err := xdr.SafeUnmarshalBase64(b64, &scVal); err != nil {
// 		return "", fmt.Errorf("unmarshal: %w", err)
// 	}
// 	return formatScVal(scVal), nil
// }

// func formatScVal(val xdr.ScVal) string {
// 	switch val.Type {
// 	case xdr.ScValTypeScvBool:
// 		return fmt.Sprintf("bool(%v)", *val.B)
// 	case xdr.ScValTypeScvVoid:
// 		return "void"
// 	case xdr.ScValTypeScvU32:
// 		return fmt.Sprintf("u32(%d)", *val.U32)
// 	case xdr.ScValTypeScvI32:
// 		return fmt.Sprintf("i32(%d)", *val.I32)
// 	case xdr.ScValTypeScvU64:
// 		return fmt.Sprintf("u64(%d)", *val.U64)
// 	case xdr.ScValTypeScvI64:
// 		return fmt.Sprintf("i64(%d)", *val.I64)
// 	case xdr.ScValTypeScvU128:
// 		hi := big.NewInt(0).SetUint64(uint64(val.U128.Hi))
// 		hi.Lsh(hi, 64)
// 		lo := new(big.Int).SetUint64(uint64(val.U128.Lo))
// 		return fmt.Sprintf("u128(%s)", hi.Add(hi, lo).String())
// 	case xdr.ScValTypeScvI128:
// 		hi := big.NewInt(int64(val.I128.Hi))
// 		hi.Lsh(hi, 64)
// 		lo := new(big.Int).SetUint64(uint64(val.I128.Lo))
// 		return fmt.Sprintf("i128(%s)", hi.Add(hi, lo).String())
// 	case xdr.ScValTypeScvBytes:
// 		return fmt.Sprintf("bytes(%x)", *val.Bytes)
// 	case xdr.ScValTypeScvString:
// 		return fmt.Sprintf("string(%q)", string(*val.Str))
// 	case xdr.ScValTypeScvSymbol:
// 		return fmt.Sprintf("symbol(%s)", string(*val.Sym))
// 	case xdr.ScValTypeScvAddress:
// 		addr, _ := scAddressToStrkey(*val.Address)
// 		return fmt.Sprintf("address(%s)", addr)
// 	case xdr.ScValTypeScvVec:
// 		if val.Vec == nil || *val.Vec == nil {
// 			return "vec([])"
// 		}
// 		items := make([]string, len(**val.Vec))
// 		for i, item := range **val.Vec {
// 			items[i] = formatScVal(item)
// 		}
// 		return fmt.Sprintf("vec([%s])", strings.Join(items, ", "))
// 	case xdr.ScValTypeScvMap:
// 		if val.Map == nil || *val.Map == nil {
// 			return "map({})"
// 		}
// 		items := make([]string, len(**val.Map))
// 		for i, entry := range **val.Map {
// 			items[i] = fmt.Sprintf("%s: %s", formatScVal(entry.Key), formatScVal(entry.Val))
// 		}
// 		return fmt.Sprintf("map({%s})", strings.Join(items, ", "))
// 	default:
// 		return fmt.Sprintf("%s(?)", val.Type)
// 	}
// }

// func scAddressToStrkey(addr xdr.ScAddress) (string, error) {
// 	switch addr.Type {
// 	case xdr.ScAddressTypeScAddressTypeAccount:
// 		accountID := addr.MustAccountId()
// 		pubKey := accountID.Ed25519
// 		if pubKey == nil {
// 			return "", fmt.Errorf("no Ed25519 key")
// 		}
// 		return strkey.Encode(strkey.VersionByteAccountID, (*pubKey)[:])
// 	case xdr.ScAddressTypeScAddressTypeContract:
// 		contractID := addr.MustContractId()
// 		return strkey.Encode(strkey.VersionByteContract, contractID[:])
// 	default:
// 		return fmt.Sprintf("unknown(%s)", addr.Type), nil
// 	}
// }

// decodeTransferEvent decodes a transfer event from XDR topics and value.
// Expected: topics[1]=Address(from), topics[2]=Address(to), value=i128(amount).
func decodeTransferEvent(topicsXDR []string, valueXDR string) (*TransferEvent, error) {
	if len(topicsXDR) < 3 {
		return nil, fmt.Errorf("transfer event requires at least 3 topics, got %d", len(topicsXDR))
	}

	// topic1: from address
	from, err := decodeAddress(topicsXDR[1])
	if err != nil {
		return nil, fmt.Errorf("decode from address: %w", err)
	}

	// topic2: to address
	to, err := decodeAddress(topicsXDR[2])
	if err != nil {
		return nil, fmt.Errorf("decode to address: %w", err)
	}

	// value: i128 amount
	amount, err := decodeI128(valueXDR)
	if err != nil {
		return nil, fmt.Errorf("decode amount: %w", err)
	}

	return &TransferEvent{
		From:   from,
		To:     to,
		Amount: amount,
	}, nil
}

// decodeAddress decodes a base64 XDR ScVal containing an address to strkey format.
func decodeAddress(topicB64 string) (string, error) {
	var scVal xdr.ScVal
	if err := xdr.SafeUnmarshalBase64(topicB64, &scVal); err != nil {
		return "", fmt.Errorf("unmarshal: %w", err)
	}

	addr, ok := scVal.GetAddress()
	if !ok {
		return "", fmt.Errorf("not an address (type=%s)", scVal.Type)
	}

	switch addr.Type {
	case xdr.ScAddressTypeScAddressTypeAccount:
		accountID := addr.MustAccountId()
		pubKey := accountID.Ed25519
		if pubKey == nil {
			return "", fmt.Errorf("account ID has no Ed25519 key")
		}
		return strkey.Encode(strkey.VersionByteAccountID, (*pubKey)[:])
	case xdr.ScAddressTypeScAddressTypeContract:
		contractID := addr.MustContractId()
		return strkey.Encode(strkey.VersionByteContract, contractID[:])
	default:
		return "", fmt.Errorf("unsupported address type: %s", addr.Type)
	}
}

// decodeI128 decodes a base64 XDR ScVal containing an i128 value to *big.Int.
func decodeI128(valueB64 string) (*big.Int, error) {
	var scVal xdr.ScVal
	if err := xdr.SafeUnmarshalBase64(valueB64, &scVal); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	i128, ok := scVal.GetI128()
	if !ok {
		return nil, fmt.Errorf("not i128 (type=%s)", scVal.Type)
	}

	// Convert Int128Parts (hi: int64, lo: uint64) to *big.Int
	// value = hi * 2^64 + lo
	hi := big.NewInt(int64(i128.Hi))
	hi.Lsh(hi, 64)
	lo := new(big.Int).SetUint64(uint64(i128.Lo))
	return hi.Add(hi, lo), nil
}

// GetBlocksHeaders returns the block headers for the requested ledger sequence numbers.
func (s *SourceReader) GetBlocksHeaders(ctx context.Context, ledgerNumber []*big.Int) (map[*big.Int]protocol.BlockHeader, error) {
	headers := make(map[*big.Int]protocol.BlockHeader, len(ledgerNumber))

	for _, n := range ledgerNumber {
		seq := n.Uint64()
		if seq > math.MaxUint32 {
			return nil, fmt.Errorf("block number exceeds uint32 (ledger seq) range: %d", seq)
		}

		req := protocolrpc.GetLedgersRequest{
			StartLedger: uint32(seq),
			Pagination: &protocolrpc.LedgerPaginationOptions{
				Limit: 1,
			},
		}

		resp, err := s.client.GetLedgers(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to get ledger %d: %w", seq, err)
		}
		if len(resp.Ledgers) == 0 {
			return nil, fmt.Errorf("ledger %d not found", seq)
		}
		ledger := resp.Ledgers[0]
		if ledger.Sequence != uint32(seq) {
			return nil, fmt.Errorf("ledger seq mismatch: requested %d got %d", seq, ledger.Sequence)
		}

		blockHeader, err := buildBlockHeaderFromMeta(ledger.Hash, ledger.LedgerMetadata, ledger.Sequence, ledger.LedgerCloseTime)
		if err != nil {
			return nil, fmt.Errorf("failed to build header for ledger %d: %w", seq, err)
		}
		headers[n] = blockHeader
	}

	return headers, nil
}

// LatestAndFinalizedBlock returns the latest and finalized ledger headers.
// Stellar does not have re-orgs, so the latest and finalized ledger headers are the same.
func (s *SourceReader) LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error) {
	latestLedger, err := s.client.GetLatestLedger(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get latest ledger: %w", err)
	}

	header, err := ledgerToBlockHeader(latestLedger)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build block header: %w", err)
	}

	// Stellar ledgers are finalized on close; latest == finalized.
	return &header, &header, nil
}

// GetRMNCursedSubjects is currently a stub; fill in once the Stellar RMN
// contract/location is defined.
func (s *SourceReader) GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error) {
	return nil, fmt.Errorf("GetRMNCursedSubjects not implemented for stellar")
}

// toBytes32 normalizes a hex string (with or without 0x prefix) into protocol.Bytes32.
func toBytes32(hexStr string) (protocol.Bytes32, error) {
	if !strings.HasPrefix(hexStr, "0x") {
		hexStr = "0x" + strings.TrimPrefix(hexStr, "0X")
	}

	// Allow odd-length hex by left-padding if needed.
	h := strings.TrimPrefix(hexStr, "0x")
	if len(h)%2 == 1 {
		h = "0" + h
	}
	if len(h) > 64 {
		return protocol.Bytes32{}, fmt.Errorf("hex string too long: %s", hexStr)
	}

	decoded, err := hex.DecodeString(h)
	if err != nil {
		return protocol.Bytes32{}, fmt.Errorf("decode hex: %w", err)
	}

	var out protocol.Bytes32
	copy(out[:], decoded)
	return out, nil
}

// ledgerToBlockHeader converts a GetLatestLedgerResponse into a protocol.BlockHeader.
func ledgerToBlockHeader(resp protocolrpc.GetLatestLedgerResponse) (protocol.BlockHeader, error) {
	return buildBlockHeader(resp.Hash, resp.LedgerHeader, resp.Sequence, resp.LedgerCloseTime)
}

// buildBlockHeader constructs a BlockHeader from ledger fields.
// For GetLatestLedger, headerB64 contains xdr.LedgerHeader.
func buildBlockHeader(hashHex, headerB64 string, sequence uint32, closeTime int64) (protocol.BlockHeader, error) {
	var hdr xdr.LedgerHeader
	if err := xdr.SafeUnmarshalBase64(headerB64, &hdr); err != nil {
		return protocol.BlockHeader{}, fmt.Errorf("unmarshal ledger header: %w", err)
	}

	hash, err := toBytes32(hashHex)
	if err != nil {
		return protocol.BlockHeader{}, fmt.Errorf("parse ledger hash: %w", err)
	}

	return protocol.BlockHeader{
		Number:     uint64(sequence),
		Hash:       hash,
		ParentHash: protocol.Bytes32(hdr.PreviousLedgerHash),
		Timestamp:  time.Unix(closeTime, 0).UTC(),
	}, nil
}

// buildBlockHeaderFromMeta constructs a BlockHeader from GetLedgers response using metadata.
// GetLedgers returns LedgerCloseMeta in metadataXdr which contains header info.
func buildBlockHeaderFromMeta(hashHex, metadataB64 string, sequence uint32, closeTime int64) (protocol.BlockHeader, error) {
	var lcm xdr.LedgerCloseMeta
	if err := xdr.SafeUnmarshalBase64(metadataB64, &lcm); err != nil {
		return protocol.BlockHeader{}, fmt.Errorf("unmarshal ledger metadata: %w", err)
	}

	hash, err := toBytes32(hashHex)
	if err != nil {
		return protocol.BlockHeader{}, fmt.Errorf("parse ledger hash: %w", err)
	}

	// Extract previous ledger hash using the helper method (handles all versions)
	headerEntry := lcm.LedgerHeaderHistoryEntry()
	previousHash := headerEntry.Header.PreviousLedgerHash

	return protocol.BlockHeader{
		Number:     uint64(sequence),
		Hash:       hash,
		ParentHash: protocol.Bytes32(previousHash),
		Timestamp:  time.Unix(closeTime, 0).UTC(),
	}, nil
}

// symbolScVal builds an ScVal representing a Soroban symbol topic.
// Soroban symbols are ASCII strings up to 32 bytes.
func symbolScVal(sym string) (*xdr.ScVal, error) {
	scSym := xdr.ScSymbol(sym)
	return &xdr.ScVal{
		Type: xdr.ScValTypeScvSymbol,
		Sym:  &scSym,
	}, nil
}
