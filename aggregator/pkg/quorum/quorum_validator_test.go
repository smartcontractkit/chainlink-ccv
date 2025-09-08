package quorum_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/quorum"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	fixtures "github.com/smartcontractkit/chainlink-ccv/aggregator/tests"
)

// copyMessageWithCCVNodeData safely copies MessageWithCCVNodeData without mutex issues.
func copyMessageWithCCVNodeData(src *aggregator.MessageWithCCVNodeData) aggregator.MessageWithCCVNodeData {
	return aggregator.MessageWithCCVNodeData{
		MessageId:             src.MessageId,
		SourceVerifierAddress: src.SourceVerifierAddress,
		DestVerifierAddress:   src.DestVerifierAddress,
		Message:               src.Message,
		BlobData:              src.BlobData,
		CcvData:               src.CcvData,
		Timestamp:             src.Timestamp,
		ReceiptBlobs:          src.ReceiptBlobs,
	}
}

// TestCaseBuilder helps build test cases using option pattern.
type TestCaseBuilder struct {
	signerFixtures []*fixtures.SignerFixture
	committeeID    string
	verifications  []string // participant IDs that signed
	f              uint8
	expectedValid  bool
	expectedError  bool
}

// TestCaseOption defines an option for configuring test cases.
type TestCaseOption func(*TestCaseBuilder)

// WithSignerFixtures sets the signer fixtures for the committee.
func WithSignerFixtures(fixtures ...*fixtures.SignerFixture) TestCaseOption {
	return func(b *TestCaseBuilder) {
		b.signerFixtures = fixtures
	}
}

// WithF sets the fault tolerance value.
func WithF(f uint8) TestCaseOption {
	return func(b *TestCaseBuilder) {
		b.f = f
	}
}

// WithCommitteeID sets the committee ID.
func WithCommitteeID(id string) TestCaseOption {
	return func(b *TestCaseBuilder) {
		b.committeeID = id
	}
}

// WithVerifications sets which signers actually signed (by participant ID).
func WithVerifications(participantIDs ...string) TestCaseOption {
	return func(b *TestCaseBuilder) {
		b.verifications = participantIDs
	}
}

// ExpectValid sets the expected validation result.
func ExpectValid(valid bool) TestCaseOption {
	return func(b *TestCaseBuilder) {
		b.expectedValid = valid
	}
}

// ExpectError sets whether an error is expected.
func ExpectError() TestCaseOption {
	return func(b *TestCaseBuilder) {
		b.expectedError = true
	}
}

// NewTestCase creates a new test case builder with defaults.
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

// BuildConfig creates the AggregatorConfig from the builder.
func (b *TestCaseBuilder) BuildConfig() *model.AggregatorConfig {
	signers := make([]model.Signer, len(b.signerFixtures))
	for i, fixture := range b.signerFixtures {
		signers[i] = fixture.Signer
	}

	return &model.AggregatorConfig{
		Committees: map[string]*model.Committee{
			b.committeeID: {
				QuorumConfigs: map[uint64]*model.QuorumConfig{
					1: {
						OfframpAddress: make([]byte, 20),
						Signers:        signers,
						F:              b.f,
					},
				},
			},
		},
	}
}

// BuildReport creates the CommitAggregatedReport from the builder.
func (b *TestCaseBuilder) BuildReport(t *testing.T) *model.CommitAggregatedReport {
	verifications := make([]*model.CommitVerificationRecord, len(b.verifications))

	for i, participantID := range b.verifications {
		// Find the fixture for this participant
		var signerFixture *fixtures.SignerFixture
		for _, fixture := range b.signerFixtures {
			if fixture.Signer.ParticipantID == participantID {
				signerFixture = fixture
				break
			}
		}

		if signerFixture == nil {
			// Create a dummy verification record for unknown signers
			verifications[i] = &model.CommitVerificationRecord{
				MessageWithCCVNodeData: aggregator.MessageWithCCVNodeData{
					MessageId: []byte{1},
					Message: &aggregator.Message{
						DestChainSelector: 1,
					},
				},
			}
			continue
		}

		// Create a proper signed verification record
		protocolMessage := fixtures.NewProtocolMessage(t, func(m *types.Message) *types.Message {
			m.DestChainSelector = 1 // Match the config
			return m
		})

		messageData := fixtures.NewMessageWithCCVNodeData(t, protocolMessage,
			fixtures.WithSignatureFrom(t, signerFixture))

		verificationRecord := &model.CommitVerificationRecord{}
		// Use safe copy to avoid mutex copy issues
		verificationRecord.MessageWithCCVNodeData = copyMessageWithCCVNodeData(messageData)
		verifications[i] = verificationRecord
	}

	return &model.CommitAggregatedReport{
		Verifications: verifications,
	}
}

// Run executes the test case.
func (b *TestCaseBuilder) Run(t *testing.T) {
	config := b.BuildConfig()
	validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))
	report := b.BuildReport(t)

	ctx := context.Background()
	valid, err := validator.CheckQuorum(ctx, report)

	if b.expectedError {
		assert.Error(t, err)
	} else {
		assert.NoError(t, err)
		assert.Equal(t, b.expectedValid, valid)
	}
}

func TestValidateSignature(t *testing.T) {
	// Create signer fixture
	signerFixture := fixtures.NewSignerFixture(t, "signer1")
	committeeID := "committee1"

	// Create test message using fixture
	protocolMessage := fixtures.NewProtocolMessage(t)

	// Create MessageWithCCVNodeData using fixtures with signature
	messageData := fixtures.NewMessageWithCCVNodeData(t, protocolMessage,
		fixtures.WithSignatureFrom(t, signerFixture))

	t.Run("valid signature", func(t *testing.T) {
		// Setup validator with test configuration
		config := &model.AggregatorConfig{
			Committees: map[string]*model.Committee{
				committeeID: {
					QuorumConfigs: map[uint64]*model.QuorumConfig{
						uint64(protocolMessage.DestChainSelector): {
							Signers:        []model.Signer{signerFixture.Signer},
							F:              0,
							OfframpAddress: make([]byte, 20),
						},
					},
				},
			},
		}

		validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

		// Create verification record with valid signature
		record := &model.CommitVerificationRecord{}
		record.MessageWithCCVNodeData = copyMessageWithCCVNodeData(messageData)

		signers, _, err := validator.ValidateSignature(context.Background(), &record.MessageWithCCVNodeData)
		assert.NoError(t, err)
		assert.NotNil(t, signers)
		assert.Equal(t, signerFixture.Signer.ParticipantID, signers[0].ParticipantID)
		assert.Equal(t, signerFixture.Signer.Addresses, signers[0].Addresses)
	})

	t.Run("missing signature", func(t *testing.T) {
		config := &model.AggregatorConfig{
			Committees: map[string]*model.Committee{
				committeeID: {
					QuorumConfigs: map[uint64]*model.QuorumConfig{
						uint64(protocolMessage.DestChainSelector): {
							Signers:        []model.Signer{signerFixture.Signer},
							F:              0,
							OfframpAddress: make([]byte, 20),
						},
					},
				},
			},
		}

		validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

		// Create message data without signature
		messageDataNoSig := fixtures.NewMessageWithCCVNodeData(t, protocolMessage)
		messageDataNoSig.CcvData = nil // Remove signature

		record := &model.CommitVerificationRecord{}
		record.MessageWithCCVNodeData = copyMessageWithCCVNodeData(messageDataNoSig)

		signer, _, err := validator.ValidateSignature(context.Background(), &record.MessageWithCCVNodeData)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "missing signature in report")
	})

	t.Run("invalid signature", func(t *testing.T) {
		config := &model.AggregatorConfig{
			Committees: map[string]*model.Committee{
				committeeID: {
					QuorumConfigs: map[uint64]*model.QuorumConfig{
						uint64(protocolMessage.DestChainSelector): {
							Signers:        []model.Signer{signerFixture.Signer},
							F:              0,
							OfframpAddress: make([]byte, 20),
						},
					},
				},
			},
		}

		validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

		// Create different signer for invalid signature
		invalidSignerFixture := fixtures.NewSignerFixture(t, "invalid_signer")
		invalidMessageData := fixtures.NewMessageWithCCVNodeData(t, protocolMessage,
			fixtures.WithSignatureFrom(t, invalidSignerFixture))

		record := &model.CommitVerificationRecord{}
		record.MessageWithCCVNodeData = copyMessageWithCCVNodeData(invalidMessageData)

		signer, _, err := validator.ValidateSignature(context.Background(), &record.MessageWithCCVNodeData)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "no valid signers found for the provided signature")
	})

	t.Run("missing committee config", func(t *testing.T) {
		// Empty configuration
		config := &model.AggregatorConfig{
			Committees: map[string]*model.Committee{},
		}

		validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

		record := &model.CommitVerificationRecord{}
		record.MessageWithCCVNodeData = copyMessageWithCCVNodeData(messageData)

		signer, _, err := validator.ValidateSignature(context.Background(), &record.MessageWithCCVNodeData)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "quorum config not found for chain selector")
	})

	t.Run("missing receipt blob", func(t *testing.T) {
		config := &model.AggregatorConfig{
			Committees: map[string]*model.Committee{
				committeeID: {
					QuorumConfigs: map[uint64]*model.QuorumConfig{
						uint64(protocolMessage.DestChainSelector): {
							Signers:        []model.Signer{signerFixture.Signer},
							F:              0,
							OfframpAddress: make([]byte, 20),
						},
					},
				},
			},
		}

		validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

		// Create message data without receipt blobs
		messageDataNoBlob := fixtures.NewMessageWithCCVNodeData(t, protocolMessage,
			fixtures.WithSignatureFrom(t, signerFixture))
		messageDataNoBlob.ReceiptBlobs = []*aggregator.ReceiptBlob{} // Empty receipt blobs

		record := &model.CommitVerificationRecord{}
		record.MessageWithCCVNodeData = copyMessageWithCCVNodeData(messageDataNoBlob)

		signer, _, err := validator.ValidateSignature(context.Background(), &record.MessageWithCCVNodeData)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "receipt blob not found for verifier")
	})
}

func TestCheckQuorum(t *testing.T) {
	tests := []struct {
		name          string
		signers       []string
		verifications []string
		f             uint8
		expectedValid bool
	}{
		{
			name:          "single signer, f=0, one verification",
			signers:       []string{"signer1"},
			f:             0,
			verifications: []string{"signer1"},
			expectedValid: true,
		},
		{
			name:          "single signer, f=0, no verification",
			signers:       []string{"signer1"},
			f:             0,
			verifications: []string{},
			expectedValid: false,
		},
		{
			name:          "three signers, f=1, two verifications",
			signers:       []string{"signer1", "signer2", "signer3"},
			f:             1,
			verifications: []string{"signer1", "signer2"},
			expectedValid: true,
		},
		{
			name:          "three signers, f=1, one verification (insufficient)",
			signers:       []string{"signer1", "signer2", "signer3"},
			f:             1,
			verifications: []string{"signer1"},
			expectedValid: false,
		},
		{
			name:          "three signers, f=0, two verification (too many)",
			signers:       []string{"signer1", "signer2", "signer3"},
			f:             0,
			verifications: []string{"signer1", "signer2"},
			expectedValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create signer fixtures based on test case
			signerFixtures := make([]*fixtures.SignerFixture, len(tt.signers))
			for i, signerName := range tt.signers {
				signerFixtures[i] = fixtures.NewSignerFixture(t, signerName)
			}

			NewTestCase(
				WithSignerFixtures(signerFixtures...),
				WithF(tt.f),
				WithVerifications(tt.verifications...),
				ExpectValid(tt.expectedValid),
			).Run(t)
		})
	}
}
