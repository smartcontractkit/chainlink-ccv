package tests

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	committee "github.com/smartcontractkit/chainlink-ccv/committee/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// DeriveUUIDFromString creates a deterministic UUID from a string for testing.
func DeriveUUIDFromString(input string) string {
	hash := sha256.Sum256([]byte(input))
	// Use first 16 bytes to create a UUID
	return uuid.UUID(hash[:16]).String()
}

// DeriveUUIDFromTimestamp creates a deterministic UUID from a timestamp for testing.
func DeriveUUIDFromTimestamp(timestamp int64) string {
	buf := make([]byte, 8)
	// Safe conversion: use absolute value to avoid issues with negative timestamps
	var ts uint64
	if timestamp < 0 {
		ts = uint64(-timestamp)
	} else {
		ts = uint64(timestamp)
	}
	binary.LittleEndian.PutUint64(buf, ts)
	hash := sha256.Sum256(buf)
	return uuid.UUID(hash[:16]).String()
}

func GenerateVerifierAddresses(t *testing.T) ([]byte, []byte) {
	// Generate valid Ethereum addresses using private keys
	sourceKey, err := crypto.GenerateKey()
	require.NoError(t, err, "failed to generate source private key")
	sourceVerifierAddress := crypto.PubkeyToAddress(sourceKey.PublicKey)

	destKey, err := crypto.GenerateKey()
	require.NoError(t, err, "failed to generate destination private key")
	destVerifierAddress := crypto.PubkeyToAddress(destKey.PublicKey)

	return sourceVerifierAddress.Bytes(), destVerifierAddress.Bytes()
}

type SignerFixture struct {
	key    *ecdsa.PrivateKey
	Signer model.Signer
}

func NewSignerFixture(t *testing.T, name string) *SignerFixture {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err, "failed to generate private key")

	signerAddress := crypto.PubkeyToAddress(privateKey.PublicKey)

	signer := model.Signer{
		ParticipantID: name,
		Addresses:     []string{signerAddress.Hex()},
	}
	return &SignerFixture{
		Signer: signer,
		key:    privateKey,
	}
}

type ProtocolMessageOption = func(*protocol.Message) *protocol.Message

func WithNonce(nonce uint64) ProtocolMessageOption {
	return func(m *protocol.Message) *protocol.Message {
		m.Nonce = protocol.Nonce(nonce)
		return m
	}
}

func NewProtocolMessage(t *testing.T, options ...ProtocolMessageOption) *protocol.Message {
	msg := &protocol.Message{
		Version:              1,
		SourceChainSelector:  1,
		DestChainSelector:    2,
		Nonce:                123,
		OnRampAddressLength:  20,
		OnRampAddress:        make([]byte, 20),
		OffRampAddressLength: 20,
		OffRampAddress:       make([]byte, 20),
		Finality:             10,
		SenderLength:         20,
		Sender:               make([]byte, 20),
		ReceiverLength:       20,
		Receiver:             make([]byte, 20),
		DestBlobLength:       10,
		DestBlob:             make([]byte, 10),
		TokenTransferLength:  0,
		TokenTransfer:        []byte{},
		DataLength:           8,
		Data:                 []byte("testdata"),
	}

	for _, opt := range options {
		msg = opt(msg)
	}

	return msg
}

type MessageWithCCVNodeDataOption = func(*pb.MessageWithCCVNodeData) *pb.MessageWithCCVNodeData

func WithCustomTimestamp(timestamp int64) MessageWithCCVNodeDataOption {
	return func(m *pb.MessageWithCCVNodeData) *pb.MessageWithCCVNodeData {
		m.Timestamp = timestamp
		return m
	}
}

func WithReceiptBlobs(receiptBlobs []*pb.ReceiptBlob) MessageWithCCVNodeDataOption {
	return func(m *pb.MessageWithCCVNodeData) *pb.MessageWithCCVNodeData {
		m.ReceiptBlobs = receiptBlobs
		return m
	}
}

func WithSignatureFrom(t *testing.T, signer *SignerFixture) MessageWithCCVNodeDataOption {
	return func(m *pb.MessageWithCCVNodeData) *pb.MessageWithCCVNodeData {
		protocolMessage := model.MapProtoMessageToProtocolMessage(m.Message)

		// Get message hash
		messageID, err := protocolMessage.MessageID()
		require.NoError(t, err, "failed to get message ID")

		// Create dummy ccvArgs (nonce as 8 bytes) - must be done before signing
		ccvArgs := make([]byte, 8)
		binary.BigEndian.PutUint64(ccvArgs, 123) // dummy nonce

		// Use SignV27 for proper signature creation and normalization
		require.Len(t, m.BlobData, 4, "blob data must be at least 4 bytes to account for version")
		hash, err := committee.NewSignableHash(messageID, m.BlobData)
		require.NoError(t, err, "failed to create signed hash")
		r32, s32, signerAddr, err := protocol.SignV27(hash[:], signer.key)
		require.NoError(t, err, "failed to sign message")

		// Create signature data with actual signer address
		sigData := []protocol.Data{
			{
				R:      r32,
				S:      s32,
				Signer: signerAddr,
			},
		}

		m.CcvData, err = protocol.EncodeSignatures(sigData)
		require.NoError(t, err, "failed to encode signatures")

		return m
	}
}

func WithBlobData(blobData []byte) MessageWithCCVNodeDataOption {
	return func(m *pb.MessageWithCCVNodeData) *pb.MessageWithCCVNodeData {
		m.BlobData = blobData
		return m
	}
}

func NewMessageWithCCVNodeData(t *testing.T, message *protocol.Message, sourceVerifierAddress []byte, options ...MessageWithCCVNodeDataOption) *pb.MessageWithCCVNodeData {
	messageID, err := message.MessageID()
	require.NoError(t, err, "failed to compute message ID")

	// blob data must be at least 4 bytes to account for version
	blobData := []byte{0x01, 0x02, 0x03, 0x04}

	ccvNodeData := &pb.MessageWithCCVNodeData{
		MessageId:             messageID[:],
		SourceVerifierAddress: sourceVerifierAddress,
		Message: &pb.Message{
			Version:              uint32(message.Version),
			SourceChainSelector:  uint64(message.SourceChainSelector),
			DestChainSelector:    uint64(message.DestChainSelector),
			Nonce:                uint64(message.Nonce),
			OnRampAddressLength:  uint32(message.OnRampAddressLength),
			OnRampAddress:        message.OnRampAddress[:],
			OffRampAddressLength: uint32(message.OffRampAddressLength),
			OffRampAddress:       message.OffRampAddress[:],
			Finality:             uint32(message.Finality),
			GasLimit:             message.GasLimit,
			SenderLength:         uint32(message.SenderLength),
			Sender:               message.Sender[:],
			ReceiverLength:       uint32(message.ReceiverLength),
			Receiver:             message.Receiver[:],
			DestBlobLength:       uint32(message.DestBlobLength),
			DestBlob:             message.DestBlob[:],
			TokenTransferLength:  uint32(message.TokenTransferLength),
			TokenTransfer:        message.TokenTransfer[:],
			DataLength:           uint32(message.DataLength),
			Data:                 message.Data[:],
		},
		BlobData:  blobData,
		CcvData:   []byte("test ccv data"),
		Timestamp: time.Now().UnixMilli(),
		ReceiptBlobs: []*pb.ReceiptBlob{
			{
				Issuer: sourceVerifierAddress,
				Blob:   blobData,
			},
		},
	}
	for _, opt := range options {
		ccvNodeData = opt(ccvNodeData)
	}
	return ccvNodeData
}

// NewWriteCommitCCVNodeDataRequest creates a new WriteCommitCCVNodeDataRequest with a generated idempotency key.
func NewWriteCommitCCVNodeDataRequest(ccvNodeData *pb.MessageWithCCVNodeData) *pb.WriteCommitCCVNodeDataRequest {
	return &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData:    ccvNodeData,
		IdempotencyKey: uuid.New().String(),
	}
}

// NewWriteCommitCCVNodeDataRequestWithKey creates a new WriteCommitCCVNodeDataRequest with a specific idempotency key.
func NewWriteCommitCCVNodeDataRequestWithKey(ccvNodeData *pb.MessageWithCCVNodeData, idempotencyKey string) *pb.WriteCommitCCVNodeDataRequest {
	return &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData:    ccvNodeData,
		IdempotencyKey: idempotencyKey,
	}
}
