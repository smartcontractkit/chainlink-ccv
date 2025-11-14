package quorum_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/quorum"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	fixtures "github.com/smartcontractkit/chainlink-ccv/aggregator/tests"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

const destSelector = "2" // Using string keys for QuorumConfigs map

// Helper function to create a commit verification record from protobuf message.
func createCommitVerificationRecord(messageData *pb.MessageWithCCVNodeData) *model.CommitVerificationRecord {
	record := model.CommitVerificationRecordFromProto(messageData)
	return record
}

// TestCaseBuilder helps build test cases using option pattern.
type TestCaseBuilder struct {
	committeeID           string
	signerFixtures        []*fixtures.SignerFixture
	verifications         []string
	sourceVerifierAddress []byte
	destVerifierAddress   []byte
	threshold             uint8
	expectedValid         bool
	expectedError         bool
}

// TestCaseOption defines an option for configuring test cases.
type TestCaseOption func(*TestCaseBuilder)

// WithSignerFixtures sets the signer fixtures for the committee.
func WithSignerFixtures(fixtures ...*fixtures.SignerFixture) TestCaseOption {
	return func(b *TestCaseBuilder) {
		b.signerFixtures = fixtures
	}
}

// WithThreshold sets the fault tolerance value.
func WithThreshold(threshold uint8) TestCaseOption {
	return func(b *TestCaseBuilder) {
		b.threshold = threshold
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
func NewTestCase(t *testing.T, opts ...TestCaseOption) *TestCaseBuilder {
	sourceVerifierAddress, destVerifierAddress := fixtures.GenerateVerifierAddresses(t)
	b := &TestCaseBuilder{
		committeeID:           "committee1",
		threshold:             1,
		expectedValid:         true,
		expectedError:         false,
		sourceVerifierAddress: sourceVerifierAddress,
		destVerifierAddress:   destVerifierAddress,
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
		Committee: &model.Committee{
			QuorumConfigs: map[string]*model.QuorumConfig{
				"1": {
					CommitteeVerifierAddress: common.Bytes2Hex(b.destVerifierAddress),
					Signers:                  signers,
					Threshold:                b.threshold,
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
				MessageID:             []byte{1},
				SourceVerifierAddress: b.sourceVerifierAddress,
				Message: &protocol.Message{
					DestChainSelector: 1,
				},
			}
			continue
		}

		// Create a proper signed verification record
		protocolMessage := fixtures.NewProtocolMessage(t, func(m *protocol.Message) *protocol.Message {
			m.DestChainSelector = 1 // Match the config
			return m
		})

		messageData := fixtures.NewMessageWithCCVNodeData(t, protocolMessage, b.sourceVerifierAddress,
			fixtures.WithSignatureFrom(t, signerFixture))

		verificationRecord := createCommitVerificationRecord(messageData)
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
	sourceVerifierAddress, destVerifierAddress := fixtures.GenerateVerifierAddresses(t)
	// Create signer fixture
	signerFixture := fixtures.NewSignerFixture(t, "signer1")

	// Create test message using fixture
	protocolMessage := fixtures.NewProtocolMessage(t)

	// Create MessageWithCCVNodeData using fixtures with signature
	messageData := fixtures.NewMessageWithCCVNodeData(t, protocolMessage, sourceVerifierAddress,
		fixtures.WithSignatureFrom(t, signerFixture))

	t.Run("valid signature", func(t *testing.T) {
		// Setup validator with test configuration
		config := &model.AggregatorConfig{
			Committee: &model.Committee{
				QuorumConfigs: map[string]*model.QuorumConfig{
					destSelector: {
						Signers:                  []model.Signer{signerFixture.Signer},
						Threshold:                1,
						CommitteeVerifierAddress: common.Bytes2Hex(destVerifierAddress),
					},
				},
			},
		}

		validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

		// Convert protobuf to domain model for validation
		record := model.CommitVerificationRecordFromProto(messageData)
		signers, _, err := validator.ValidateSignature(context.Background(), record)
		assert.NoError(t, err)
		assert.NotNil(t, signers)
		assert.Equal(t, signerFixture.Signer.ParticipantID, signers[0].ParticipantID)
		assert.Equal(t, common.Hex2Bytes(strings.TrimPrefix(signerFixture.Signer.Addresses[0], "0x")), signers[0].Address)
	})

	t.Run("missing signature", func(t *testing.T) {
		config := &model.AggregatorConfig{
			Committee: &model.Committee{
				QuorumConfigs: map[string]*model.QuorumConfig{
					destSelector: {
						Signers:                  []model.Signer{signerFixture.Signer},
						Threshold:                1,
						CommitteeVerifierAddress: common.Bytes2Hex(destVerifierAddress),
					},
				},
			},
		}

		validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

		// Create message data without signature
		messageDataNoSig := fixtures.NewMessageWithCCVNodeData(t, protocolMessage, sourceVerifierAddress)
		messageDataNoSig.CcvData = nil // Remove signature

		// Convert protobuf to domain model for validation
		recordNoSig := model.CommitVerificationRecordFromProto(messageDataNoSig)
		signer, _, err := validator.ValidateSignature(context.Background(), recordNoSig)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "missing signature in report")
	})

	t.Run("invalid signature", func(t *testing.T) {
		config := &model.AggregatorConfig{
			Committee: &model.Committee{
				QuorumConfigs: map[string]*model.QuorumConfig{
					destSelector: {
						Signers:                  []model.Signer{signerFixture.Signer},
						Threshold:                1,
						CommitteeVerifierAddress: common.Bytes2Hex(destVerifierAddress),
					},
				},
			},
		}

		validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

		// Create different signer for invalid signature
		invalidSignerFixture := fixtures.NewSignerFixture(t, "invalid_signer")
		invalidMessageData := fixtures.NewMessageWithCCVNodeData(t, protocolMessage, sourceVerifierAddress,
			fixtures.WithSignatureFrom(t, invalidSignerFixture))

		// Convert protobuf to domain model for validation
		invalidRecord := model.CommitVerificationRecordFromProto(invalidMessageData)
		signer, _, err := validator.ValidateSignature(context.Background(), invalidRecord)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "no valid signers found for the provided signature")
	})

	t.Run("missing committee config", func(t *testing.T) {
		// Empty configuration
		config := &model.AggregatorConfig{
			Committee: nil,
		}

		validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

		// Convert protobuf to domain model for validation
		record := model.CommitVerificationRecordFromProto(messageData)
		signer, _, err := validator.ValidateSignature(context.Background(), record)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "committee config not found")
	})

	t.Run("receipt blob is not part of the signature", func(t *testing.T) {
		config := &model.AggregatorConfig{
			Committee: &model.Committee{
				QuorumConfigs: map[string]*model.QuorumConfig{
					destSelector: {
						Signers:                  []model.Signer{signerFixture.Signer},
						Threshold:                1,
						CommitteeVerifierAddress: common.Bytes2Hex(destVerifierAddress),
					},
				},
			},
		}

		validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

		// Create message data without receipt blobs
		messageDataNoBlob := fixtures.NewMessageWithCCVNodeData(t, protocolMessage, sourceVerifierAddress,
			fixtures.WithSignatureFrom(t, signerFixture))
		messageDataNoBlob.ReceiptBlobs = []*pb.ReceiptBlob{} // Empty receipt blobs

		// Convert protobuf to domain model for validation
		recordNoBlob := model.CommitVerificationRecordFromProto(messageDataNoBlob)
		signers, _, err := validator.ValidateSignature(context.Background(), recordNoBlob)
		assert.NoError(t, err)
		assert.NotNil(t, signers)
		assert.Equal(t, signerFixture.Signer.ParticipantID, signers[0].ParticipantID)
		assert.Equal(t, common.Hex2Bytes(strings.TrimPrefix(signerFixture.Signer.Addresses[0], "0x")), signers[0].Address)
	})
}

func TestCheckQuorum(t *testing.T) {
	tests := []struct {
		name          string
		signers       []string
		verifications []string
		threshold     uint8
		expectedValid bool
	}{
		{
			name:          "single signer, threshold=1, one verification",
			signers:       []string{"signer1"},
			threshold:     1,
			verifications: []string{"signer1"},
			expectedValid: true,
		},
		{
			name:          "single signer, threshold=1, no verification",
			signers:       []string{"signer1"},
			threshold:     1,
			verifications: []string{},
			expectedValid: false,
		},
		{
			name:          "three signers, threshold=2, two verifications",
			signers:       []string{"signer1", "signer2", "signer3"},
			threshold:     2,
			verifications: []string{"signer1", "signer2"},
			expectedValid: true,
		},
		{
			name:          "three signers, threshold=2, one verification (insufficient)",
			signers:       []string{"signer1", "signer2", "signer3"},
			threshold:     2,
			verifications: []string{"signer1"},
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
				t,
				WithSignerFixtures(signerFixtures...),
				WithThreshold(tt.threshold),
				WithVerifications(tt.verifications...),
				ExpectValid(tt.expectedValid),
			).Run(t)
		})
	}
}
