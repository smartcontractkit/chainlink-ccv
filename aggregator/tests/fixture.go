package tests

import (
	"bytes"
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

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

func (sf *SignerFixture) Sign(t *testing.T, message *types.Message, verifierBlob []byte) ([]byte, []byte, error) {
	messageHash, err := message.MessageID()
	assert.NoError(t, err)

	// Calculate signature hash (message hash || keccak256(verifierBlob))
	verifierBlobHash := crypto.Keccak256(verifierBlob)
	var signatureHashInput bytes.Buffer
	signatureHashInput.Write(messageHash[:])
	signatureHashInput.Write(verifierBlobHash)
	signatureHash := crypto.Keccak256(signatureHashInput.Bytes())

	// Create valid signature
	validSignature, err := crypto.Sign(signatureHash, sf.key)
	assert.NoError(t, err)

	// Encode signature in the expected format
	// Note: crypto.Sign returns [R || S || V] where V is the recovery ID
	rBytes := [32]byte{}
	sBytes := [32]byte{}
	copy(rBytes[:], validSignature[0:32])
	copy(sBytes[:], validSignature[32:64])
	return rBytes[:], sBytes[:], nil
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

type ProtocolMessageOption = func(*types.Message) *types.Message

func NewProtocolMessage(t *testing.T, options ...ProtocolMessageOption) *types.Message {
	msg := &types.Message{
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

type MessageWithCCVNodeDataOption = func(*aggregator.MessageWithCCVNodeData) *aggregator.MessageWithCCVNodeData

func WithSignatureFrom(t *testing.T, signer *SignerFixture) MessageWithCCVNodeDataOption {
	return func(m *aggregator.MessageWithCCVNodeData) *aggregator.MessageWithCCVNodeData {
		protocolMessage := model.MapProtoMessageToProtocolMessage(m.Message)

		r, s, err := signer.Sign(t, protocolMessage, m.BlobData)
		require.NoError(t, err, "failed to sign message")

		to32ByteArray := func(b []byte) [32]byte {
			var arr [32]byte
			copy(arr[:], b)
			return arr
		}

		m.CcvData, err = model.EncodeSignatures([][32]byte{to32ByteArray(r)}, [][32]byte{to32ByteArray(s)})
		require.NoError(t, err, "failed to encode signatures")

		return m
	}
}

func NewMessageWithCCVNodeData(t *testing.T, message *types.Message, sourceVerifierAddress []byte, options ...MessageWithCCVNodeDataOption) *aggregator.MessageWithCCVNodeData {
	messageID, err := message.MessageID()
	require.NoError(t, err, "failed to compute message ID")

	ccvNodeData := &aggregator.MessageWithCCVNodeData{
		MessageId:             messageID[:],
		SourceVerifierAddress: sourceVerifierAddress,
		Message: &aggregator.Message{
			Version:              uint32(message.Version),
			SourceChainSelector:  uint64(message.SourceChainSelector),
			DestChainSelector:    uint64(message.DestChainSelector),
			Nonce:                uint64(message.Nonce),
			OnRampAddressLength:  uint32(message.OnRampAddressLength),
			OnRampAddress:        message.OnRampAddress[:],
			OffRampAddressLength: uint32(message.OffRampAddressLength),
			OffRampAddress:       message.OffRampAddress[:],
			Finality:             uint32(message.Finality),
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
		BlobData:  []byte("test blob data"),
		CcvData:   []byte("test ccv data"),
		Timestamp: 1234567890,
		ReceiptBlobs: []*aggregator.ReceiptBlob{
			{
				Issuer: sourceVerifierAddress,
				Blob:   []byte("test blob data"),
			},
		},
	}
	for _, opt := range options {
		ccvNodeData = opt(ccvNodeData)
	}
	return ccvNodeData
}
