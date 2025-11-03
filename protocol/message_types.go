package protocol

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
)

// Constants for CCIP v1.7.
const (
	MaxNumTokens                  = 1
	MaxDataSize                   = 1024 // 1kb
	MessageVersion                = 1    // Current message format version
	MinSizeRequiredMsgFields      = 27   // Minimum size for required fields in Message
	MinSizeRequiredMsgTokenFields = 34   // Minimum size for required fields in TokenTransfer
)

// TokenTransfer represents a chain-agnostic token transfer with canonical encoding.
type TokenTransfer struct {
	Amount                   *big.Int  `json:"amount"`
	SourceTokenAddress       ByteSlice `json:"source_token_address"`
	DestTokenAddress         ByteSlice `json:"dest_token_address"`
	TokenReceiver            ByteSlice `json:"token_receiver"`
	ExtraData                ByteSlice `json:"extra_data"`
	Version                  uint8     `json:"version"`
	SourceTokenAddressLength uint8     `json:"source_token_address_length"`
	DestTokenAddressLength   uint8     `json:"dest_token_address_length"`
	TokenReceiverLength      uint8     `json:"token_receiver_length"`
	ExtraDataLength          uint8     `json:"extra_data_length"`
}

// Encode returns the canonical encoding of this token transfer.
func (tt *TokenTransfer) Encode() []byte {
	var buf bytes.Buffer

	// Version (1 byte)
	_ = buf.WriteByte(tt.Version)

	// Amount (32 bytes, big-endian)
	amountBytes := make([]byte, 32)
	if tt.Amount != nil {
		tt.Amount.FillBytes(amountBytes)
	}
	_, _ = buf.Write(amountBytes)

	// Source token address
	_ = buf.WriteByte(tt.SourceTokenAddressLength)
	_, _ = buf.Write(tt.SourceTokenAddress)

	// Dest token address
	_ = buf.WriteByte(tt.DestTokenAddressLength)
	_, _ = buf.Write(tt.DestTokenAddress)

	// Token receiver
	_ = buf.WriteByte(tt.TokenReceiverLength)
	_, _ = buf.Write(tt.TokenReceiver)

	// Extra data
	_ = buf.WriteByte(tt.ExtraDataLength)
	_, _ = buf.Write(tt.ExtraData)

	return buf.Bytes()
}

// DecodeTokenTransfer decodes a TokenTransfer from bytes.
func DecodeTokenTransfer(data []byte) (*TokenTransfer, error) {
	if len(data) < MinSizeRequiredMsgTokenFields { // minimum size: version(1) + amount(32) + length(1)
		return nil, fmt.Errorf("data too short for token transfer")
	}

	reader := bytes.NewReader(data)
	tt := &TokenTransfer{}

	// Read version
	version, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	tt.Version = version

	// Read amount (32 bytes)
	amountBytes := make([]byte, 32)
	if _, err := io.ReadFull(reader, amountBytes); err != nil {
		return nil, fmt.Errorf("failed to read amount: %w", err)
	}
	tt.Amount = new(big.Int).SetBytes(amountBytes)

	// Read source token address
	sourceLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read source token address length: %w", err)
	}
	tt.SourceTokenAddressLength = sourceLen
	tt.SourceTokenAddress = make([]byte, sourceLen)
	if _, err := io.ReadFull(reader, tt.SourceTokenAddress); err != nil {
		return nil, fmt.Errorf("failed to read source token address: %w", err)
	}

	// Read dest token address
	destLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read dest token address length: %w", err)
	}
	tt.DestTokenAddressLength = destLen
	tt.DestTokenAddress = make([]byte, destLen)
	if _, err := io.ReadFull(reader, tt.DestTokenAddress); err != nil {
		return nil, fmt.Errorf("failed to read dest token address: %w", err)
	}

	// Read token receiver
	receiverLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read token receiver length: %w", err)
	}
	tt.TokenReceiverLength = receiverLen
	tt.TokenReceiver = make([]byte, receiverLen)
	if _, err := io.ReadFull(reader, tt.TokenReceiver); err != nil {
		return nil, fmt.Errorf("failed to read token receiver: %w", err)
	}

	// Read extra data
	extraLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read extra data length: %w", err)
	}
	tt.ExtraDataLength = extraLen
	tt.ExtraData = make([]byte, extraLen)
	if _, err := io.ReadFull(reader, tt.ExtraData); err != nil {
		return nil, fmt.Errorf("failed to read extra data: %w", err)
	}

	// Ensure all data was consumed
	if reader.Len() != 0 {
		return nil, fmt.Errorf("trailing bytes after decoding")
	}

	return tt, nil
}

// Message represents the chain-agnostic CCIP message format.
type Message struct {
	Sender               UnknownAddress `json:"sender"`
	Data                 ByteSlice      `json:"data"`
	OnRampAddress        UnknownAddress `json:"on_ramp_address"`
	TokenTransfer        ByteSlice      `json:"token_transfer"`
	OffRampAddress       UnknownAddress `json:"off_ramp_address"`
	DestBlob             ByteSlice      `json:"dest_blob"`
	Receiver             UnknownAddress `json:"receiver"`
	SourceChainSelector  ChainSelector  `json:"source_chain_selector"`
	DestChainSelector    ChainSelector  `json:"dest_chain_selector"`
	Nonce                Nonce          `json:"nonce"`
	Finality             uint16         `json:"finality"`
	DestBlobLength       uint16         `json:"dest_blob_length"`
	TokenTransferLength  uint16         `json:"token_transfer_length"`
	DataLength           uint16         `json:"data_length"`
	ReceiverLength       uint8          `json:"receiver_length"`
	SenderLength         uint8          `json:"sender_length"`
	Version              uint8          `json:"version"`
	OffRampAddressLength uint8          `json:"off_ramp_address_length"`
	OnRampAddressLength  uint8          `json:"on_ramp_address_length"`
}

// Encode returns the canonical encoding of this message.
func (m *Message) Encode() ([]byte, error) {
	var buf bytes.Buffer

	// Protocol header
	_ = buf.WriteByte(m.Version)

	// Chain selectors and nonce (8 bytes each, big-endian)
	if err := binary.Write(&buf, binary.BigEndian, uint64(m.SourceChainSelector)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint64(m.DestChainSelector)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint64(m.Nonce)); err != nil {
		return nil, err
	}

	// On-ramp address
	_ = buf.WriteByte(m.OnRampAddressLength)
	_, _ = buf.Write(m.OnRampAddress)

	// Off-ramp address
	_ = buf.WriteByte(m.OffRampAddressLength)
	_, _ = buf.Write(m.OffRampAddress)

	// User provided data
	if err := binary.Write(&buf, binary.BigEndian, m.Finality); err != nil {
		return nil, err
	}

	// Sender
	_ = buf.WriteByte(m.SenderLength)
	_, _ = buf.Write(m.Sender)

	// Receiver
	_ = buf.WriteByte(m.ReceiverLength)
	_, _ = buf.Write(m.Receiver)

	// Dest blob
	if err := binary.Write(&buf, binary.BigEndian, m.DestBlobLength); err != nil {
		return nil, err
	}
	_, _ = buf.Write(m.DestBlob)

	// Token transfer
	if err := binary.Write(&buf, binary.BigEndian, m.TokenTransferLength); err != nil {
		return nil, err
	}
	_, _ = buf.Write(m.TokenTransfer)

	// Data
	if err := binary.Write(&buf, binary.BigEndian, m.DataLength); err != nil {
		return nil, err
	}
	_, _ = buf.Write(m.Data)

	return buf.Bytes(), nil
}

// DecodeMessage decodes a Message from bytes.
func DecodeMessage(data []byte) (*Message, error) {
	if len(data) < MinSizeRequiredMsgFields {
		return nil, fmt.Errorf("data too short for message")
	}

	reader := bytes.NewReader(data)
	msg := &Message{}

	// Read version
	version, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	msg.Version = version

	// Read chain selectors and nonce
	var sourceChain, destChain, nonce uint64
	if err := binary.Read(reader, binary.BigEndian, &sourceChain); err != nil {
		return nil, fmt.Errorf("failed to read source chain selector: %w", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &destChain); err != nil {
		return nil, fmt.Errorf("failed to read dest chain selector: %w", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &nonce); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}

	msg.SourceChainSelector = ChainSelector(sourceChain)
	msg.DestChainSelector = ChainSelector(destChain)
	msg.Nonce = Nonce(nonce)

	// Read on-ramp address
	onRampLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read on-ramp address length: %w", err)
	}
	msg.OnRampAddressLength = onRampLen
	msg.OnRampAddress = make([]byte, onRampLen)
	if _, err := io.ReadFull(reader, msg.OnRampAddress); err != nil {
		return nil, fmt.Errorf("failed to read on-ramp address: %w", err)
	}

	// Read off-ramp address
	offRampLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read off-ramp address length: %w", err)
	}
	msg.OffRampAddressLength = offRampLen
	msg.OffRampAddress = make([]byte, offRampLen)
	if _, err := io.ReadFull(reader, msg.OffRampAddress); err != nil {
		return nil, fmt.Errorf("failed to read off-ramp address: %w", err)
	}

	// Read finality
	if err := binary.Read(reader, binary.BigEndian, &msg.Finality); err != nil {
		return nil, fmt.Errorf("failed to read finality: %w", err)
	}

	// Read sender
	senderLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read sender length: %w", err)
	}
	msg.SenderLength = senderLen
	msg.Sender = make([]byte, senderLen)
	if _, err := io.ReadFull(reader, msg.Sender); err != nil {
		return nil, fmt.Errorf("failed to read sender: %w", err)
	}

	// Read receiver
	receiverLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read receiver length: %w", err)
	}
	msg.ReceiverLength = receiverLen
	msg.Receiver = make([]byte, receiverLen)
	if _, err := io.ReadFull(reader, msg.Receiver); err != nil {
		return nil, fmt.Errorf("failed to read receiver: %w", err)
	}

	// Read dest blob
	var destBlobLen uint16
	if err := binary.Read(reader, binary.BigEndian, &destBlobLen); err != nil {
		return nil, fmt.Errorf("failed to read dest blob length: %w", err)
	}
	msg.DestBlobLength = destBlobLen
	msg.DestBlob = make([]byte, destBlobLen)
	if _, err := io.ReadFull(reader, msg.DestBlob); err != nil {
		return nil, fmt.Errorf("failed to read dest blob: %w", err)
	}

	// Read token transfer
	var tokenTransferLen uint16
	if err := binary.Read(reader, binary.BigEndian, &tokenTransferLen); err != nil {
		return nil, fmt.Errorf("failed to read token transfer length: %w", err)
	}
	msg.TokenTransferLength = tokenTransferLen
	msg.TokenTransfer = make([]byte, tokenTransferLen)
	if _, err := io.ReadFull(reader, msg.TokenTransfer); err != nil {
		return nil, fmt.Errorf("failed to read token transfer: %w", err)
	}

	// Read data
	var dataLen uint16
	if err := binary.Read(reader, binary.BigEndian, &dataLen); err != nil {
		return nil, fmt.Errorf("failed to read data length: %w", err)
	}
	msg.DataLength = dataLen
	msg.Data = make([]byte, dataLen)
	if _, err := io.ReadFull(reader, msg.Data); err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	// Ensure all data was consumed
	if reader.Len() != 0 {
		return nil, fmt.Errorf("trailing bytes after decoding")
	}

	return msg, nil
}

// MessageID returns the message ID of this message (keccak256 of the canonical encoding).
func (m *Message) MessageID() (Bytes32, error) {
	encoded, err := m.Encode()
	if err != nil {
		return Bytes32{}, err
	}
	result := Keccak256(encoded)
	return result, nil
}

// ReceiptWithBlob represents a chain-agnostic receipt with blob.
type ReceiptWithBlob struct {
	Issuer            UnknownAddress `json:"issuer"`
	Blob              ByteSlice      `json:"blob"`
	ExtraArgs         ByteSlice      `json:"extra_args"`
	DestGasLimit      uint64         `json:"dest_gas_limit"`
	DestBytesOverhead uint32         `json:"dest_bytes_overhead"`
	FeeTokenAmount    *big.Int       `json:"fee_token_amount"`
}

// CCV represents a Cross-Chain Verifier configuration.
type CCV struct {
	CCVAddress UnknownAddress
	Args       ByteSlice
	ArgsLen    uint16
}

// CCVData represents Cross-Chain Verification data.
type CCVData struct {
	SourceVerifierAddress UnknownAddress    `json:"source_verifier_address"`
	DestVerifierAddress   UnknownAddress    `json:"dest_verifier_address"`
	CCVData               ByteSlice         `json:"ccv_data"`
	BlobData              ByteSlice         `json:"blob_data"`
	ReceiptBlobs          []ReceiptWithBlob `json:"receipt_blobs"`
	Message               Message           `json:"message"`
	Nonce                 Nonce             `json:"nonce"`
	SourceChainSelector   ChainSelector     `json:"source_chain_selector"`
	DestChainSelector     ChainSelector     `json:"dest_chain_selector"`
	Timestamp             int64             `json:"timestamp"`
	MessageID             Bytes32           `json:"message_id"`
}

// QueryResponse represents the response from CCV data queries.
type QueryResponse struct {
	Timestamp *int64  `json:"timestamp,omitempty"`
	Data      CCVData `json:"data"`
}

// CCVNodeDataWriter defines the interface for verifiers to store CCV node data.
type CCVNodeDataWriter interface {
	// WriteCCVNodeData stores multiple CCV node data entries in the offchain storage
	// idempotencyKeys should have the same length as ccvDataList, with each key corresponding to the CCVData at the same index
	WriteCCVNodeData(ctx context.Context, ccvDataList []CCVData, idempotencyKeys []string) error
}

// OffchainStorageWriter defines the interface for verifiers to store CCV data.
type OffchainStorageWriter interface {
	// WriteCCVData stores multiple CCV data entries in the offchain storage
	WriteCCVData(ctx context.Context, ccvDataList []CCVData) error
}

// OffchainStorageReader defines the interface for executors to query CCV data by timestamp.
type OffchainStorageReader interface {
	// ReadCCVData returns the next available CCV data entries.
	ReadCCVData(ctx context.Context) ([]QueryResponse, error)
}

// DisconnectableReader extends OffchainStorageReader with the ability to signal disconnection.
// This is useful for readers that have a specific lifecycle (like BackfillReader) and need
// to signal when they should be removed from the scanner.
type DisconnectableReader interface {
	OffchainStorageReader

	// ShouldDisconnect returns true if this reader should be disconnected or no longer used.
	// This method should be called after each ReadCCVData call to check the readers validity.
	ShouldDisconnect() bool
}

// Helper functions for creating empty/default values

// NewEmptyTokenTransfer creates an empty token transfer.
func NewEmptyTokenTransfer() *TokenTransfer {
	return &TokenTransfer{
		Version:                  MessageVersion,
		Amount:                   big.NewInt(0),
		SourceTokenAddressLength: 0,
		SourceTokenAddress:       []byte{},
		DestTokenAddressLength:   0,
		DestTokenAddress:         []byte{},
		TokenReceiverLength:      0,
		TokenReceiver:            []byte{},
		ExtraDataLength:          0,
		ExtraData:                []byte{},
	}
}

// NewMessage creates a new message with the given parameters.
func NewMessage(
	sourceChain, destChain ChainSelector,
	nonce Nonce,
	onRampAddress, offRampAddress UnknownAddress,
	finality uint16,
	sender, receiver UnknownAddress,
	destBlob, data []byte,
	tokenTransfer *TokenTransfer,
) (*Message, error) {
	if len(onRampAddress) > math.MaxUint8 {
		return nil, fmt.Errorf("onRampAddress length exceeds maximum value")
	}
	if len(offRampAddress) > math.MaxUint8 {
		return nil, fmt.Errorf("offRampAddress length exceeds maximum value")
	}
	if len(sender) > math.MaxUint8 {
		return nil, fmt.Errorf("sender length exceeds maximum value")
	}
	if len(receiver) > math.MaxUint8 {
		return nil, fmt.Errorf("receiver length exceeds maximum value")
	}
	tokenTransferBytes := make([]byte, 0)
	if tokenTransfer != nil {
		tokenTransferBytes = tokenTransfer.Encode()
	}
	if len(tokenTransferBytes) > math.MaxUint8 {
		return nil, fmt.Errorf("tokenTransferBytes length exceeds maximum value")
	}
	if len(data) > math.MaxUint8 {
		return nil, fmt.Errorf("data length exceeds maximum value")
	}
	//nolint:gosec // all verified
	return &Message{
		Version:              MessageVersion,
		SourceChainSelector:  sourceChain,
		DestChainSelector:    destChain,
		Nonce:                nonce,
		OnRampAddressLength:  uint8(len(onRampAddress)),
		OnRampAddress:        onRampAddress.Bytes(),
		OffRampAddressLength: uint8(len(offRampAddress)),
		OffRampAddress:       offRampAddress.Bytes(),
		Finality:             finality,
		SenderLength:         uint8(len(sender)),
		Sender:               sender.Bytes(),
		ReceiverLength:       uint8(len(receiver)),
		Receiver:             receiver.Bytes(),
		DestBlobLength:       uint16(len(destBlob)),
		DestBlob:             destBlob,
		TokenTransferLength:  uint16(len(tokenTransferBytes)),
		TokenTransfer:        tokenTransferBytes,
		DataLength:           uint16(len(data)),
		Data:                 data,
	}, nil
}
