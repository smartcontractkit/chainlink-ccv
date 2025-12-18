package tests

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	committee "github.com/smartcontractkit/chainlink-ccv/committee/common"
	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
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

func NewSignerFixture(t *testing.T, name string) *SignerFixture {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err, "failed to generate private key")

	signerAddress := crypto.PubkeyToAddress(privateKey.PublicKey)

	signer := model.Signer{
		Address: signerAddress.Hex(),
	}
	return &SignerFixture{
		Signer: signer,
		key:    privateKey,
	}
}

// NewCommitteeFixture creates a test committee configuration with the given parameters.
// Uses default test chain selectors: source=1, dest=2.
// It also validates the config to populate parsed addresses.
func NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress []byte, signers ...model.Signer) *model.Committee {
	config := &model.AggregatorConfig{
		Committee: &model.Committee{
			QuorumConfigs: map[string]*model.QuorumConfig{
				"1": {
					Threshold:             uint8(len(signers)), //nolint:gosec // Test fixture with controlled values
					Signers:               signers,
					SourceVerifierAddress: common.BytesToAddress(sourceVerifierAddress).Hex(),
				},
			},
			DestinationVerifiers: map[string]string{
				"2": common.BytesToAddress(destVerifierAddress).Hex(),
			},
		},
	}
	// Validate to populate parsed addresses
	_ = config.ValidateCommitteeConfig()
	return config.Committee
}

// UpdateCommitteeQuorum updates the quorum config for source chain selector "1" and re-validates.
// This should be used instead of directly modifying committee.QuorumConfigs to ensure parsed addresses are populated.
func UpdateCommitteeQuorum(committee *model.Committee, sourceVerifierAddress []byte, signers ...model.Signer) {
	committee.QuorumConfigs["1"] = &model.QuorumConfig{
		Threshold:             uint8(len(signers)), //nolint:gosec // Test fixture with controlled values
		Signers:               signers,
		SourceVerifierAddress: common.BytesToAddress(sourceVerifierAddress).Hex(),
	}
	// Re-validate to populate parsed addresses
	config := &model.AggregatorConfig{Committee: committee}
	_ = config.ValidateCommitteeConfig()
}

type ProtocolMessageOption = func(*protocol.Message) *protocol.Message

func WithSequenceNumber(seq uint64) ProtocolMessageOption {
	return func(m *protocol.Message) *protocol.Message {
		m.SequenceNumber = protocol.SequenceNumber(seq)
		return m
	}
}

func NewProtocolMessage(t *testing.T, options ...ProtocolMessageOption) *protocol.Message {
	msg := &protocol.Message{
		Version:              1,
		SourceChainSelector:  1,
		DestChainSelector:    2,
		SequenceNumber:       123,
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
		TokenTransfer:        nil,
		DataLength:           8,
		Data:                 []byte("testdata"),
	}

	for _, opt := range options {
		msg = opt(msg)
	}

	return msg
}

type MessageWithCCVNodeDataOption = func(*committeepb.CommitteeVerifierNodeResult) *committeepb.CommitteeVerifierNodeResult

func WithSignatureFrom(t *testing.T, signer *SignerFixture) MessageWithCCVNodeDataOption {
	return func(m *committeepb.CommitteeVerifierNodeResult) *committeepb.CommitteeVerifierNodeResult {
		protocolMessage, err := ccvcommon.MapProtoMessageToProtocolMessage(m.Message)
		require.NoError(t, err)

		messageID, err := protocolMessage.MessageID()
		require.NoError(t, err, "failed to get message ID")

		require.Len(t, m.CcvVersion, 4, "ccv version must be at least 4 bytes")
		hash, err := committee.NewSignableHash(messageID, m.CcvVersion)
		require.NoError(t, err, "failed to create signed hash")

		r32, s32, signerAddr, err := protocol.SignV27(hash[:], signer.key)
		require.NoError(t, err, "failed to sign message for signer %s", signer.Signer.Address)

		sigData := protocol.Data{
			R:      r32,
			S:      s32,
			Signer: signerAddr,
		}

		m.Signature, err = protocol.EncodeSingleEcdsaSignature(sigData)
		require.NoError(t, err, "failed to encode single signature")

		return m
	}
}

func WithCcvVersion(ccvVersion []byte) MessageWithCCVNodeDataOption {
	return func(m *committeepb.CommitteeVerifierNodeResult) *committeepb.CommitteeVerifierNodeResult {
		m.CcvVersion = ccvVersion
		return m
	}
}

func WithCcvAddresses(t *testing.T, ccvAddresses [][]byte) MessageWithCCVNodeDataOption {
	return func(m *committeepb.CommitteeVerifierNodeResult) *committeepb.CommitteeVerifierNodeResult {
		// Convert to UnknownAddress for hash computation
		unknownAddrs := make([]protocol.UnknownAddress, len(ccvAddresses))
		for i, addr := range ccvAddresses {
			unknownAddrs[i] = protocol.UnknownAddress(addr)
		}

		// Recompute the CCV and executor hash with new addresses
		ccvAndExecutorHash, err := protocol.ComputeCCVAndExecutorHash(unknownAddrs, protocol.UnknownAddress(m.ExecutorAddress))
		require.NoError(t, err, "failed to compute CCV and executor hash")

		m.CcvAddresses = ccvAddresses
		m.Message.CcvAndExecutorHash = ccvAndExecutorHash[:]
		return m
	}
}

func NewMessageWithCCVNodeData(t *testing.T, message *protocol.Message, sourceVerifierAddress []byte, options ...MessageWithCCVNodeDataOption) (*committeepb.CommitteeVerifierNodeResult, protocol.Bytes32) {
	ccvVersion := []byte{0x01, 0x02, 0x03, 0x04}
	executorAddr := make([]byte, 20)

	// Compute the CCV and executor hash
	ccvAddrs := []protocol.UnknownAddress{protocol.UnknownAddress(sourceVerifierAddress)}
	ccvAndExecutorHash, err := protocol.ComputeCCVAndExecutorHash(ccvAddrs, protocol.UnknownAddress(executorAddr))
	require.NoError(t, err, "failed to compute CCV and executor hash")

	var tokenTransferBytes []byte
	if message.TokenTransfer != nil {
		tokenTransferBytes = message.TokenTransfer.Encode()
	}

	ccvNodeData := &committeepb.CommitteeVerifierNodeResult{
		Message: &verifierpb.Message{
			Version:              uint32(message.Version),
			SourceChainSelector:  uint64(message.SourceChainSelector),
			DestChainSelector:    uint64(message.DestChainSelector),
			SequenceNumber:       uint64(message.SequenceNumber),
			OnRampAddressLength:  uint32(message.OnRampAddressLength),
			OnRampAddress:        message.OnRampAddress[:],
			OffRampAddressLength: uint32(message.OffRampAddressLength),
			OffRampAddress:       message.OffRampAddress[:],
			Finality:             uint32(message.Finality),
			ExecutionGasLimit:    message.ExecutionGasLimit,
			CcipReceiveGasLimit:  message.CcipReceiveGasLimit,
			CcvAndExecutorHash:   ccvAndExecutorHash[:],
			SenderLength:         uint32(message.SenderLength),
			Sender:               message.Sender[:],
			ReceiverLength:       uint32(message.ReceiverLength),
			Receiver:             message.Receiver[:],
			DestBlobLength:       uint32(message.DestBlobLength),
			DestBlob:             message.DestBlob[:],
			TokenTransferLength:  uint32(len(tokenTransferBytes)), //nolint:gosec // G115: Test fixture with bounded data
			TokenTransfer:        tokenTransferBytes,
			DataLength:           uint32(message.DataLength),
			Data:                 message.Data[:],
		},
		CcvVersion:      ccvVersion,
		CcvAddresses:    [][]byte{sourceVerifierAddress},
		ExecutorAddress: executorAddr,
		Signature:       []byte("placeholder signature"),
	}
	for _, opt := range options {
		ccvNodeData = opt(ccvNodeData)
	}

	// Compute and return the message ID
	protocolMessage, err := ccvcommon.MapProtoMessageToProtocolMessage(ccvNodeData.GetMessage())
	require.NoError(t, err, "failed to map proto message")
	messageID, err := protocolMessage.MessageID()
	require.NoError(t, err, "failed to compute message ID")

	return ccvNodeData, messageID
}

func NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData *committeepb.CommitteeVerifierNodeResult) *committeepb.WriteCommitteeVerifierNodeResultRequest {
	return &committeepb.WriteCommitteeVerifierNodeResultRequest{
		CommitteeVerifierNodeResult: ccvNodeData,
	}
}
