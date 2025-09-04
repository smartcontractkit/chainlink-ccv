package quorum_test

import (
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/quorum"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/stretchr/testify/assert"
)

// TestCaseBuilder helps build test cases using option pattern
type TestCaseBuilder struct {
	signers       []*model.Signer
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
		b.signers = make([]*model.Signer, len(participantIDs))
		for i, id := range participantIDs {
			b.signers[i] = &model.Signer{ParticipantID: id}
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
				QuorumConfigs: map[uint64]model.QuorumConfig{
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

	for i, participantID := range b.verifications {
		verifications[i] = &model.CommitVerificationRecord{
			ParticipantID:            participantID,
			CommitteeID:              b.committeeID,
			CommitVerificationRecord: aggregator.CommitVerificationRecord{MessageId: []byte{1}, DestChainSelector: 1},
		}
	}

	return &model.CommitAggregatedReport{
		CommitteeID:   b.committeeID,
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
