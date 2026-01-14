package quorum_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/quorum"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	fixtures "github.com/smartcontractkit/chainlink-ccv/aggregator/tests"
	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

const (
	sourceSelector = "1" // Using string keys for QuorumConfigs map
	destSelector   = "2" // Using string keys for QuorumConfigs map
)

// Helper function to create a commit verification record from protobuf message.
func createCommitVerificationRecord(messageData *committeepb.CommitteeVerifierNodeResult) *model.CommitVerificationRecord {
	record, _ := model.CommitVerificationRecordFromProto(messageData)
	return record
}

// TestCaseBuilder helps build test cases using option pattern.
type TestCaseBuilder struct {
	committeeID           string
	signerFixtures        []*fixtures.SignerFixture
	verifications         []int
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

// WithVerifications sets which signers actually signed (by index in the signerFixtures array).
func WithVerifications(indices ...int) TestCaseOption {
	return func(b *TestCaseBuilder) {
		b.verifications = indices
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
				sourceSelector: {
					Signers:   signers,
					Threshold: b.threshold,
				},
			},
			DestinationVerifiers: map[string]string{
				"1": common.Bytes2Hex(b.destVerifierAddress),
			},
		},
	}
}

// BuildReport creates the CommitAggregatedReport from the builder.
func (b *TestCaseBuilder) BuildReport(t *testing.T) *model.CommitAggregatedReport {
	verifications := make([]*model.CommitVerificationRecord, len(b.verifications))

	for i, signerIdx := range b.verifications {
		if signerIdx >= len(b.signerFixtures) {
			t.Fatalf("Invalid signer index %d, only have %d fixtures", signerIdx, len(b.signerFixtures))
		}

		signerFixture := b.signerFixtures[signerIdx]

		// Create a proper signed verification record
		protocolMessage := fixtures.NewProtocolMessage(t, func(m *protocol.Message) *protocol.Message {
			m.DestChainSelector = 1 // Match the config
			return m
		})

		messageData, _ := fixtures.NewMessageWithCCVNodeData(t, protocolMessage, b.sourceVerifierAddress,
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
	messageData, _ := fixtures.NewMessageWithCCVNodeData(t, protocolMessage, sourceVerifierAddress,
		fixtures.WithSignatureFrom(t, signerFixture))

	t.Run("valid signature", func(t *testing.T) {
		// Setup validator with test configuration
		config := &model.AggregatorConfig{
			Committee: &model.Committee{
				QuorumConfigs: map[string]*model.QuorumConfig{
					sourceSelector: {
						Signers:   []model.Signer{signerFixture.Signer},
						Threshold: 1,
					},
				},
				DestinationVerifiers: map[string]string{
					destSelector: common.Bytes2Hex(destVerifierAddress),
				},
			},
		}

		validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

		// Convert protobuf to domain model for validation
		record, err := model.CommitVerificationRecordFromProto(messageData)
		require.NoError(t, err)
		result, err := validator.ValidateSignature(context.Background(), record)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotNil(t, result.Signer)
		assert.NotEqual(t, model.SignableHash{}, result.Hash)
		assert.Equal(t, protocol.ByteSlice(common.Hex2Bytes(strings.TrimPrefix(signerFixture.Signer.Address, "0x"))), result.Signer.Identifier)
	})

	t.Run("missing signature", func(t *testing.T) {
		config := &model.AggregatorConfig{
			Committee: &model.Committee{
				QuorumConfigs: map[string]*model.QuorumConfig{
					sourceSelector: {
						Signers:   []model.Signer{signerFixture.Signer},
						Threshold: 1,
					},
				},
				DestinationVerifiers: map[string]string{
					destSelector: common.Bytes2Hex(destVerifierAddress),
				},
			},
		}

		validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

		// Create message data without signature
		messageDataNoSig, _ := fixtures.NewMessageWithCCVNodeData(t, protocolMessage, sourceVerifierAddress)
		messageDataNoSig.Signature = nil // Remove signature

		// Convert protobuf to domain model for validation
		recordNoSig, err := model.CommitVerificationRecordFromProto(messageDataNoSig)
		require.NoError(t, err)
		result, err := validator.ValidateSignature(context.Background(), recordNoSig)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "missing signature in report")
	})

	t.Run("invalid signature", func(t *testing.T) {
		config := &model.AggregatorConfig{
			Committee: &model.Committee{
				QuorumConfigs: map[string]*model.QuorumConfig{
					sourceSelector: {
						Signers:   []model.Signer{signerFixture.Signer},
						Threshold: 1,
					},
				},
				DestinationVerifiers: map[string]string{
					destSelector: common.Bytes2Hex(destVerifierAddress),
				},
			},
		}

		validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

		// Create different signer for invalid signature
		invalidSignerFixture := fixtures.NewSignerFixture(t, "invalid_signer")
		invalidMessageData, _ := fixtures.NewMessageWithCCVNodeData(t, protocolMessage, sourceVerifierAddress,
			fixtures.WithSignatureFrom(t, invalidSignerFixture))

		// Convert protobuf to domain model for validation
		invalidRecord, err := model.CommitVerificationRecordFromProto(invalidMessageData)
		require.NoError(t, err)
		result, err := validator.ValidateSignature(context.Background(), invalidRecord)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "no valid signers found for the provided signature")
	})

	t.Run("missing committee config", func(t *testing.T) {
		// Empty configuration
		config := &model.AggregatorConfig{
			Committee: nil,
		}

		validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

		// Convert protobuf to domain model for validation
		record, err := model.CommitVerificationRecordFromProto(messageData)
		require.NoError(t, err)
		result, err := validator.ValidateSignature(context.Background(), record)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "committee config not found")
	})
}

func TestCheckQuorum(t *testing.T) {
	tests := []struct {
		name          string
		signers       []string
		verifications []int
		threshold     uint8
		expectedValid bool
	}{
		{
			name:          "single signer, threshold=1, one verification",
			signers:       []string{"signer1"},
			threshold:     1,
			verifications: []int{0},
			expectedValid: true,
		},
		{
			name:          "single signer, threshold=1, no verification",
			signers:       []string{"signer1"},
			threshold:     1,
			verifications: []int{},
			expectedValid: false,
		},
		{
			name:          "three signers, threshold=2, two verifications",
			signers:       []string{"signer1", "signer2", "signer3"},
			threshold:     2,
			verifications: []int{0, 1},
			expectedValid: true,
		},
		{
			name:          "three signers, threshold=2, one verification (insufficient)",
			signers:       []string{"signer1", "signer2", "signer3"},
			threshold:     2,
			verifications: []int{0},
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

func TestCheckQuorum_HashMismatchDetection(t *testing.T) {
	sourceVerifierAddress, destVerifierAddress := fixtures.GenerateVerifierAddresses(t)

	signer1 := fixtures.NewSignerFixture(t, "signer1")
	signer2 := fixtures.NewSignerFixture(t, "signer2")

	config := &model.AggregatorConfig{
		Committee: &model.Committee{
			QuorumConfigs: map[string]*model.QuorumConfig{
				sourceSelector: {
					Signers:   []model.Signer{signer1.Signer, signer2.Signer},
					Threshold: 2,
				},
			},
			DestinationVerifiers: map[string]string{
				destSelector: common.Bytes2Hex(destVerifierAddress),
			},
		},
	}

	validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

	// Create first verification with one message
	protocolMessage1 := fixtures.NewProtocolMessage(t, func(m *protocol.Message) *protocol.Message {
		m.DestChainSelector = 1
		return m
	})
	messageData1, _ := fixtures.NewMessageWithCCVNodeData(t, protocolMessage1, sourceVerifierAddress,
		fixtures.WithSignatureFrom(t, signer1))
	record1, err := model.CommitVerificationRecordFromProto(messageData1)
	require.NoError(t, err)

	// Create second verification with a different CCVVersion (different hash)
	// Note: WithCcvVersion must be applied BEFORE WithSignatureFrom since signature depends on CCVVersion
	protocolMessage2 := fixtures.NewProtocolMessage(t, func(m *protocol.Message) *protocol.Message {
		m.DestChainSelector = 1
		return m
	})
	messageData2, _ := fixtures.NewMessageWithCCVNodeData(t, protocolMessage2, sourceVerifierAddress,
		fixtures.WithCcvVersion([]byte{0xFF, 0xFF, 0xFF, 0xFF}),
		fixtures.WithSignatureFrom(t, signer2))
	record2, err := model.CommitVerificationRecordFromProto(messageData2)
	require.NoError(t, err)

	report := &model.CommitAggregatedReport{
		Verifications: []*model.CommitVerificationRecord{record1, record2},
	}

	valid, err := validator.CheckQuorum(context.Background(), report)

	assert.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "verification hash mismatch")
	assert.Contains(t, err.Error(), "possible data tampering")
}

func TestDeriveAggregationKey(t *testing.T) {
	sourceVerifierAddress, destVerifierAddress := fixtures.GenerateVerifierAddresses(t)
	signerFixture := fixtures.NewSignerFixture(t, "signer1")

	config := &model.AggregatorConfig{
		Committee: &model.Committee{
			QuorumConfigs: map[string]*model.QuorumConfig{
				sourceSelector: {
					Signers:   []model.Signer{signerFixture.Signer},
					Threshold: 1,
				},
			},
			DestinationVerifiers: map[string]string{
				destSelector: common.Bytes2Hex(destVerifierAddress),
			},
		},
	}

	validator := quorum.NewQuorumValidator(config, logger.TestSugared(t))

	t.Run("derives aggregation key as hex encoded hash", func(t *testing.T) {
		protocolMessage := fixtures.NewProtocolMessage(t)
		messageData, _ := fixtures.NewMessageWithCCVNodeData(t, protocolMessage, sourceVerifierAddress,
			fixtures.WithSignatureFrom(t, signerFixture))

		record, err := model.CommitVerificationRecordFromProto(messageData)
		require.NoError(t, err)

		key, err := validator.DeriveAggregationKey(context.Background(), record)
		require.NoError(t, err)
		assert.NotEmpty(t, key)
		assert.Len(t, key, 64) // 32 bytes = 64 hex chars
	})

	t.Run("same message produces same key", func(t *testing.T) {
		protocolMessage := fixtures.NewProtocolMessage(t)
		messageData1, _ := fixtures.NewMessageWithCCVNodeData(t, protocolMessage, sourceVerifierAddress,
			fixtures.WithSignatureFrom(t, signerFixture))
		messageData2, _ := fixtures.NewMessageWithCCVNodeData(t, protocolMessage, sourceVerifierAddress,
			fixtures.WithSignatureFrom(t, signerFixture))

		record1, err := model.CommitVerificationRecordFromProto(messageData1)
		require.NoError(t, err)
		record2, err := model.CommitVerificationRecordFromProto(messageData2)
		require.NoError(t, err)

		key1, err := validator.DeriveAggregationKey(context.Background(), record1)
		require.NoError(t, err)
		key2, err := validator.DeriveAggregationKey(context.Background(), record2)
		require.NoError(t, err)

		assert.Equal(t, key1, key2)
	})

	t.Run("different messages produce different keys", func(t *testing.T) {
		protocolMessage1 := fixtures.NewProtocolMessage(t, fixtures.WithSequenceNumber(1))
		protocolMessage2 := fixtures.NewProtocolMessage(t, fixtures.WithSequenceNumber(2))

		messageData1, _ := fixtures.NewMessageWithCCVNodeData(t, protocolMessage1, sourceVerifierAddress,
			fixtures.WithSignatureFrom(t, signerFixture))
		messageData2, _ := fixtures.NewMessageWithCCVNodeData(t, protocolMessage2, sourceVerifierAddress,
			fixtures.WithSignatureFrom(t, signerFixture))

		record1, err := model.CommitVerificationRecordFromProto(messageData1)
		require.NoError(t, err)
		record2, err := model.CommitVerificationRecordFromProto(messageData2)
		require.NoError(t, err)

		key1, err := validator.DeriveAggregationKey(context.Background(), record1)
		require.NoError(t, err)
		key2, err := validator.DeriveAggregationKey(context.Background(), record2)
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2)
	})
}
