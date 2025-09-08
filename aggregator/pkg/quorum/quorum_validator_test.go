package quorum_test

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/quorum"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/stretchr/testify/assert"
)

// TestCaseBuilder helps build test cases using option pattern
type TestCaseBuilder struct {
	signers       []model.Signer
	f             uint8
	committeeID   string
	verifications []string // participant IDs that signed
	expectedValid bool
	expectedError bool
}

// TestCaseOption defines an option for configuring test cases
type TestCaseOption func(*TestCaseBuilder)

// WithSigners sets the signers for the committee
func WithSigners(participantIDs ...string) TestCaseOption {
	return func(b *TestCaseBuilder) {
		b.signers = make([]model.Signer, len(participantIDs))
		for i, id := range participantIDs {
			b.signers[i] = model.Signer{ParticipantID: id}
		}
	}
}

// WithF sets the fault tolerance value
func WithF(f uint8) TestCaseOption {
	return func(b *TestCaseBuilder) {
		b.f = f
	}
}

// WithCommitteeID sets the committee ID
func WithCommitteeID(id string) TestCaseOption {
	return func(b *TestCaseBuilder) {
		b.committeeID = id
	}
}

// WithVerifications sets which signers actually signed (by participant ID)
func WithVerifications(participantIDs ...string) TestCaseOption {
	return func(b *TestCaseBuilder) {
		b.verifications = participantIDs
	}
}

// ExpectValid sets the expected validation result
func ExpectValid(valid bool) TestCaseOption {
	return func(b *TestCaseBuilder) {
		b.expectedValid = valid
	}
}

// ExpectError sets whether an error is expected
func ExpectError() TestCaseOption {
	return func(b *TestCaseBuilder) {
		b.expectedError = true
	}
}

// NewTestCase creates a new test case builder with defaults
func NewTestCase(opts ...TestCaseOption) *TestCaseBuilder {
	b := &TestCaseBuilder{
		committeeID:   "committee1",
		f:             0,
		expectedValid: true,
		expectedError: false,
	}

	for _, opt := range opts {
		opt(b)
	}

	return b
}

// BuildConfig creates the AggregatorConfig from the builder
func (b *TestCaseBuilder) BuildConfig() model.AggregatorConfig {
	return model.AggregatorConfig{
		Committees: map[string]model.Committee{
			b.committeeID: {
				QuorumConfigs: map[uint64]*model.QuorumConfig{
					1: {
						Signers: b.signers,
						F:       b.f,
					},
				},
			},
		},
	}
}

// BuildReport creates the CommitAggregatedReport from the builder
func (b *TestCaseBuilder) BuildReport() *model.CommitAggregatedReport {
	verifications := make([]*model.CommitVerificationRecord, len(b.verifications))

	for i, _ := range b.verifications {
		verifications[i] = &model.CommitVerificationRecord{
			MessageWithCCVNodeData: aggregator.MessageWithCCVNodeData{MessageId: []byte{1}, Message: &aggregator.Message{
				DestChainSelector: 1,
			}},
		}
	}

	return &model.CommitAggregatedReport{
		Verifications: verifications,
	}
}

// Run executes the test case
func (b *TestCaseBuilder) Run(t *testing.T) {
	config := b.BuildConfig()
	validator := quorum.NewQuorumValidator(config)
	report := b.BuildReport()

	valid, err := validator.CheckQuorum(report)

	if b.expectedError {
		assert.Error(t, err)
	} else {
		assert.NoError(t, err)
		assert.Equal(t, b.expectedValid, valid)
	}
}

func TestValidateSignature(t *testing.T) {
	// Create test ECDSA private key and signer
	privateKey, err := crypto.GenerateKey()
	assert.NoError(t, err)

	signerAddress := crypto.PubkeyToAddress(privateKey.PublicKey)

	// Setup test data
	participantID := "signer1"
	committeeID := "committee1"
	messageID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	sourceVerifierAddress := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	destVerifierAddress := []byte{21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40}

	// Create verifier blob (nonce encoded)
	verifierBlob := []byte{12}

	// Create test message
	testMessage := &aggregator.Message{
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
		TokenTransfer:        []byte{},
		DataLength:           8,
		Data:                 []byte("testdata"),
	}

	// Convert to protocol message and calculate message hash
	protocolMessage := types.Message{
		Version:              uint8(testMessage.Version),
		SourceChainSelector:  types.ChainSelector(testMessage.SourceChainSelector),
		DestChainSelector:    types.ChainSelector(testMessage.DestChainSelector),
		SequenceNumber:       types.SeqNum(testMessage.SequenceNumber),
		OnRampAddressLength:  uint8(testMessage.OnRampAddressLength),
		OnRampAddress:        testMessage.OnRampAddress,
		OffRampAddressLength: uint8(testMessage.OffRampAddressLength),
		OffRampAddress:       testMessage.OffRampAddress,
		Finality:             uint16(testMessage.Finality),
		SenderLength:         uint8(testMessage.SenderLength),
		Sender:               testMessage.Sender,
		ReceiverLength:       uint8(testMessage.ReceiverLength),
		Receiver:             testMessage.Receiver,
		DestBlobLength:       uint16(testMessage.DestBlobLength),
		DestBlob:             testMessage.DestBlob,
		TokenTransferLength:  uint16(testMessage.TokenTransferLength),
		TokenTransfer:        testMessage.TokenTransfer,
		DataLength:           uint16(testMessage.DataLength),
		Data:                 testMessage.Data,
	}

	messageHash, err := protocolMessage.MessageID()
	assert.NoError(t, err)

	// Calculate signature hash (message hash || keccak256(verifierBlob))
	verifierBlobHash := crypto.Keccak256(verifierBlob)
	var signatureHashInput bytes.Buffer
	signatureHashInput.Write(messageHash[:])
	signatureHashInput.Write(verifierBlobHash)
	signatureHash := crypto.Keccak256(signatureHashInput.Bytes())

	// Create valid signature
	validSignature, err := crypto.Sign(signatureHash, privateKey)
	assert.NoError(t, err)

	// Encode signature in the expected format
	// Note: crypto.Sign returns [R || S || V] where V is the recovery ID
	rBytes := [32]byte{}
	sBytes := [32]byte{}
	copy(rBytes[:], validSignature[0:32])
	copy(sBytes[:], validSignature[32:64])
	// V value is at validSignature[64] - this is the recovery ID we need

	rs := [][32]byte{rBytes}
	ss := [][32]byte{sBytes}
	encodedSignature, err := quorum.EncodeSignatures(rs, ss)
	assert.NoError(t, err)

	t.Run("valid signature", func(t *testing.T) {
		// Setup validator with test configuration
		config := model.AggregatorConfig{
			Committees: map[string]model.Committee{
				committeeID: {
					QuorumConfigs: map[uint64]*model.QuorumConfig{
						2: { // dest chain selector
							Signers: []model.Signer{
								{
									ParticipantID: participantID,
									Addresses:     []string{signerAddress.Hex()},
								},
							},
							F: 0,
						},
					},
				},
			},
		}

		validator := quorum.NewQuorumValidator(config)

		// Create verification record with valid signature
		record := &model.CommitVerificationRecord{
			MessageWithCCVNodeData: aggregator.MessageWithCCVNodeData{
				MessageId:             messageID,
				SourceVerifierAddress: sourceVerifierAddress,
				DestVerifierAddress:   destVerifierAddress,
				CcvData:               encodedSignature,
				Message:               testMessage,
				ReceiptBlobs: []*aggregator.ReceiptBlob{
					{
						Issuer: sourceVerifierAddress,
						Blob:   verifierBlob,
					},
				},
			},
		}

		signers, _, err := validator.ValidateSignature(record)
		assert.NoError(t, err)
		assert.NotNil(t, signers)
		assert.Equal(t, participantID, signers[0].ParticipantID)
		assert.Contains(t, signers[0].Addresses, signerAddress.Hex())
	})

	t.Run("missing signature", func(t *testing.T) {
		config := model.AggregatorConfig{
			Committees: map[string]model.Committee{
				committeeID: {
					QuorumConfigs: map[uint64]*model.QuorumConfig{
						2: {
							Signers: []model.Signer{
								{
									ParticipantID: participantID,
									Addresses:     []string{signerAddress.Hex()},
								},
							},
							F: 0,
						},
					},
				},
			},
		}

		validator := quorum.NewQuorumValidator(config)

		record := &model.CommitVerificationRecord{
			MessageWithCCVNodeData: aggregator.MessageWithCCVNodeData{
				MessageId:             messageID,
				SourceVerifierAddress: sourceVerifierAddress,
				DestVerifierAddress:   destVerifierAddress,
				CcvData:               nil, // Missing signature
				Message:               testMessage,
				ReceiptBlobs: []*aggregator.ReceiptBlob{
					{
						Issuer: sourceVerifierAddress,
						Blob:   verifierBlob,
					},
				},
			},
		}

		signer, _, err := validator.ValidateSignature(record)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "missing signature in report")
	})

	t.Run("invalid signature", func(t *testing.T) {
		config := model.AggregatorConfig{
			Committees: map[string]model.Committee{
				committeeID: {
					QuorumConfigs: map[uint64]*model.QuorumConfig{
						2: {
							Signers: []model.Signer{
								{
									ParticipantID: participantID,
									Addresses:     []string{signerAddress.Hex()},
								},
							},
							F: 0,
						},
					},
				},
			},
		}

		validator := quorum.NewQuorumValidator(config)

		// Create invalid signature (different message)
		invalidHash := crypto.Keccak256([]byte("invalid message"))
		invalidSignature, err := crypto.Sign(invalidHash, privateKey)
		assert.NoError(t, err)

		invalidRBytes := [32]byte{}
		invalidSBytes := [32]byte{}
		copy(invalidRBytes[:], invalidSignature[0:32])
		copy(invalidSBytes[:], invalidSignature[32:64])

		invalidRs := [][32]byte{invalidRBytes}
		invalidSs := [][32]byte{invalidSBytes}
		invalidEncodedSignature, err := quorum.EncodeSignatures(invalidRs, invalidSs)
		assert.NoError(t, err)

		record := &model.CommitVerificationRecord{
			MessageWithCCVNodeData: aggregator.MessageWithCCVNodeData{
				MessageId:             messageID,
				SourceVerifierAddress: sourceVerifierAddress,
				DestVerifierAddress:   destVerifierAddress,
				CcvData:               invalidEncodedSignature,
				Message:               testMessage,
				ReceiptBlobs: []*aggregator.ReceiptBlob{
					{
						Issuer: sourceVerifierAddress,
						Blob:   verifierBlob,
					},
				},
			},
		}

		signer, _, err := validator.ValidateSignature(record)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "no valid signers found for the provided signature")
	})

	t.Run("missing committee config", func(t *testing.T) {
		// Empty configuration
		config := model.AggregatorConfig{
			Committees: map[string]model.Committee{},
		}

		validator := quorum.NewQuorumValidator(config)

		record := &model.CommitVerificationRecord{
			MessageWithCCVNodeData: aggregator.MessageWithCCVNodeData{
				MessageId:             messageID,
				SourceVerifierAddress: sourceVerifierAddress,
				DestVerifierAddress:   destVerifierAddress,
				CcvData:               encodedSignature,
				Message:               testMessage,
				ReceiptBlobs: []*aggregator.ReceiptBlob{
					{
						Issuer: sourceVerifierAddress,
						Blob:   verifierBlob,
					},
				},
			},
		}

		signer, _, err := validator.ValidateSignature(record)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "no valid signers found for the provided signature")
	})

	t.Run("missing receipt blob", func(t *testing.T) {
		config := model.AggregatorConfig{
			Committees: map[string]model.Committee{
				committeeID: {
					QuorumConfigs: map[uint64]*model.QuorumConfig{
						2: {
							Signers: []model.Signer{
								{
									ParticipantID: participantID,
									Addresses:     []string{signerAddress.Hex()},
								},
							},
							F: 0,
						},
					},
				},
			},
		}

		validator := quorum.NewQuorumValidator(config)

		record := &model.CommitVerificationRecord{
			MessageWithCCVNodeData: aggregator.MessageWithCCVNodeData{
				MessageId:             messageID,
				SourceVerifierAddress: sourceVerifierAddress,
				DestVerifierAddress:   destVerifierAddress,
				CcvData:               encodedSignature,
				Message:               testMessage,
				ReceiptBlobs:          []*aggregator.ReceiptBlob{}, // Empty receipt blobs
			},
		}

		signer, _, err := validator.ValidateSignature(record)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "receipt blob not found for verifier")
	})
}

func TestCheckQuorumWithBuilder(t *testing.T) {
	t.Run("single signer, f=0, one verification", func(t *testing.T) {
		NewTestCase(
			WithSigners("signer1"),
			WithF(0),
			WithVerifications("signer1"),
			ExpectValid(true),
		).Run(t)
	})

	t.Run("single signer, f=0, no verification", func(t *testing.T) {
		NewTestCase(
			WithSigners("signer1"),
			WithF(0),
			WithVerifications(),
			ExpectValid(false),
		).Run(t)
	})

	t.Run("three signers, f=1, two verifications", func(t *testing.T) {
		NewTestCase(
			WithSigners("signer1", "signer2", "signer3"),
			WithF(1),
			WithVerifications("signer1", "signer2"),
			ExpectValid(true),
		).Run(t)
	})

	t.Run("three signers, f=1, one verification (insufficient)", func(t *testing.T) {
		NewTestCase(
			WithSigners("signer1", "signer2", "signer3"),
			WithF(1),
			WithVerifications("signer1"),
			ExpectValid(false),
		).Run(t)
	})

	t.Run("three signers, f=0, two verification (too many)", func(t *testing.T) {
		NewTestCase(
			WithSigners("signer1", "signer2", "signer3"),
			WithF(0),
			WithVerifications("signer1", "signer2"),
			ExpectValid(false),
		).Run(t)
	})

	// t.Run("unknown signer verification", func(t *testing.T) {
	// 	NewTestCase(
	// 		WithSigners("signer1", "signer2"),
	// 		WithF(0),
	// 		WithVerifications("unknown_signer"),
	// 		ExpectValid(false),
	// 	).Run(t)
	// })
}
