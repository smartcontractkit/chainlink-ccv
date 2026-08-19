// differential-go is a test harness for the Rust ccv-chainaccess / ccv-protocol
// crates. It exposes the Go implementation's exact behavior over stdio so the
// Rust differential tests can compare outcomes byte for byte.
//
// Modes:
//
//	message-codec   stdin: one hex-encoded canonical message per line.
//	                stdout: one JSON per line: {"ok":true,"encoded":"...","id":"0x..."}
//	                or {"ok":false,"class":"too_short|trailing|eof|other"}.
//	parse-events    stdin: {"onRampAddress":"0x..","logs":[<geth RPC log JSON>, ...]}
//	                stdout: one JSON per log: {"status":"ok","message_id":"0x..",...}
//	                or {"status":"skip","reason":"<code>"}. Reason codes match
//	                ccv_chainaccess::evm::SkipReason::code().
//
// The parse-events mode is a faithful port of the per-log pipeline in
// integration/pkg/accessors/evm/evm_source_reader.go (FetchMessageSentEvents).
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: differential-go <message-codec|parse-events>")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "message-codec":
		err = messageCodec(os.Stdin, os.Stdout)
	case "parse-events":
		err = parseEvents(os.Stdin, os.Stdout)
	default:
		fmt.Fprintln(os.Stderr, "unknown mode:", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// message-codec
// ---------------------------------------------------------------------------

type codecResult struct {
	Ok      bool   `json:"ok"`
	Class   string `json:"class,omitempty"`
	Encoded string `json:"encoded,omitempty"`
	ID      string `json:"id,omitempty"`
}

func classifyDecodeErr(err error) string {
	switch msg := err.Error(); {
	case strings.Contains(msg, "data too short"):
		return "too_short"
	case strings.Contains(msg, "trailing bytes"):
		return "trailing"
	case strings.Contains(msg, "EOF"):
		return "eof"
	default:
		return "other"
	}
}

func messageCodec(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	w := bufio.NewWriter(out)
	enc := json.NewEncoder(w)
	for scanner.Scan() {
		// Note: empty lines are valid input (empty message), not padding.
		line := strings.TrimSpace(scanner.Text())
		data, err := hex.DecodeString(line)
		if err != nil {
			return fmt.Errorf("bad hex input: %w", err)
		}
		msg, err := protocol.DecodeMessage(data)
		if err != nil {
			if err := enc.Encode(codecResult{Ok: false, Class: classifyDecodeErr(err)}); err != nil {
				return err
			}
			continue
		}
		reencoded, err := msg.Encode()
		if err != nil {
			return fmt.Errorf("re-encode of decoded message failed: %w", err)
		}
		id, err := msg.MessageID()
		if err != nil {
			return fmt.Errorf("message id of decoded message failed: %w", err)
		}
		if err := enc.Encode(codecResult{
			Ok:      true,
			Encoded: hex.EncodeToString(reencoded),
			ID:      "0x" + hex.EncodeToString(id[:]),
		}); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return w.Flush()
}

// ---------------------------------------------------------------------------
// parse-events
// ---------------------------------------------------------------------------

type parseEventsRequest struct {
	OnRampAddress string      `json:"onRampAddress"`
	Logs          []types.Log `json:"logs"`
}

type eventResult struct {
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	MessageID      string `json:"message_id,omitempty"`
	BlockNumber    uint64 `json:"block_number,omitempty"`
	TxHash         string `json:"tx_hash,omitempty"`
	Receipts       int    `json:"receipts,omitempty"`
	EncodedMessage string `json:"encoded_message,omitempty"`
}

// Skip-reason codes; must match ccv_chainaccess::evm::SkipReason::code().
const (
	reasonMalformedEvent       = "malformed_event"
	reasonInsufficientReceipts = "insufficient_receipts"
	reasonUndecodableMessage   = "undecodable_message"
	reasonZeroHash             = "zero_hash"
	reasonOnRampMismatch       = "onramp_mismatch"
	reasonSenderMismatch       = "sender_mismatch"
	reasonIDMismatch           = "id_mismatch"
	reasonDestMismatch         = "dest_mismatch"
	reasonHashValidation       = "hash_validation"
)

func expectedSourceAddressBytes(sourceAddress common.Address) []byte {
	return common.LeftPadBytes(sourceAddress[:], 32)
}

// parseEvent replicates the per-log pipeline of the Go EVM SourceReader's
// FetchMessageSentEvents (minus logging and the invariant callbacks).
func parseEvent(onRampABI *abi.ABI, onRamp common.Address, log types.Log) eventResult {
	skip := func(reason string) eventResult { return eventResult{Status: "skip", Reason: reason} }

	if len(log.Topics) < 4 {
		return skip(reasonMalformedEvent)
	}
	destChainSelector := binary.BigEndian.Uint64(log.Topics[1][24:])
	sender := common.BytesToAddress(log.Topics[2][12:])
	var messageID [32]byte
	copy(messageID[:], log.Topics[3][:])

	event := &onramp.OnRampCCIPMessageSent{}
	event.DestChainSelector = destChainSelector
	event.MessageId = messageID
	event.Sender = sender
	if err := onRampABI.UnpackIntoInterface(event, "CCIPMessageSent", log.Data); err != nil {
		return skip(reasonMalformedEvent)
	}

	if len(event.Receipts) < 3 {
		return skip(reasonInsufficientReceipts)
	}

	decodedMsg, err := protocol.DecodeMessage(event.EncodedMessage)
	if err != nil {
		return skip(reasonUndecodableMessage)
	}

	if decodedMsg.CcvAndExecutorHash == (protocol.Bytes32{}) {
		return skip(reasonZeroHash)
	}
	if !decodedMsg.OnRampAddress.Equal(expectedSourceAddressBytes(onRamp)) {
		return skip(reasonOnRampMismatch)
	}
	if !decodedMsg.Sender.Equal(expectedSourceAddressBytes(event.Sender)) {
		return skip(reasonSenderMismatch)
	}
	if decodedMsg.MustMessageID() != event.MessageId {
		return skip(reasonIDMismatch)
	}
	if decodedMsg.DestChainSelector != protocol.ChainSelector(event.DestChainSelector) {
		return skip(reasonDestMismatch)
	}

	allReceipts := receiptBlobsFromEvent(event.Receipts, event.VerifierBlobs)
	if err := protocol.ValidateCCVAndExecutorHash(*decodedMsg, allReceipts); err != nil {
		return skip(reasonHashValidation)
	}

	encoded, err := decodedMsg.Encode()
	if err != nil {
		return skip(reasonUndecodableMessage)
	}
	return eventResult{
		Status:         "ok",
		MessageID:      "0x" + hex.EncodeToString(event.MessageId[:]),
		BlockNumber:    log.BlockNumber,
		TxHash:         log.TxHash.Hex(),
		Receipts:       len(allReceipts),
		EncodedMessage: "0x" + hex.EncodeToString(encoded),
	}
}

// receiptBlobsFromEvent mirrors the helper in evm_source_reader.go.
func receiptBlobsFromEvent(eventReceipts []onramp.OnRampReceipt, verifierBlobs [][]byte) []protocol.ReceiptWithBlob {
	receipts := make([]protocol.ReceiptWithBlob, len(eventReceipts))
	for i, vr := range eventReceipts {
		var blob []byte
		if i < len(verifierBlobs) {
			blob = verifierBlobs[i]
		}
		issuerAddr, _ := protocol.NewUnknownAddressFromHex(vr.Issuer.Hex())
		receipts[i] = protocol.ReceiptWithBlob{
			Issuer:            issuerAddr,
			DestGasLimit:      uint64(vr.DestGasLimit),
			DestBytesOverhead: vr.DestBytesOverhead,
			Blob:              blob,
			ExtraArgs:         vr.ExtraArgs,
			FeeTokenAmount:    vr.FeeTokenAmount,
		}
	}
	return receipts
}

func parseEvents(in io.Reader, out io.Writer) error {
	var req parseEventsRequest
	dec := json.NewDecoder(in)
	if err := dec.Decode(&req); err != nil {
		return fmt.Errorf("bad parse-events request: %w", err)
	}
	if !common.IsHexAddress(req.OnRampAddress) {
		return fmt.Errorf("bad onRampAddress: %q", req.OnRampAddress)
	}
	onRamp := common.HexToAddress(req.OnRampAddress)

	onRampABI, err := onramp.OnRampMetaData.GetAbi()
	if err != nil {
		return fmt.Errorf("failed to load OnRamp ABI: %w", err)
	}

	w := bufio.NewWriter(out)
	enc := json.NewEncoder(w)
	for _, log := range req.Logs {
		if err := enc.Encode(parseEvent(onRampABI, onRamp, log)); err != nil {
			return err
		}
	}
	return w.Flush()
}
