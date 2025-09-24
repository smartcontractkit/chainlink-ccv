package quorum

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	aggregator "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// ValidatorStub is a stub implementation of a quorum validator for testing.
type ValidatorStub struct {
	// Add any necessary fields here
}

func (q *ValidatorStub) CheckQuorum(ctx context.Context, report *model.CommitAggregatedReport) (bool, error) {
	// Implement your quorum checking logic here
	return true, nil
}

func (q *ValidatorStub) ValidateSignature(ctx context.Context, report *aggregator.MessageWithCCVNodeData) ([]*model.IdentifierSigner, *model.QuorumConfig, error) {
	// Implement your signature validation logic here
	return []*model.IdentifierSigner{
		{
			Signer: model.Signer{
				ParticipantID: "stub-participant",
				Addresses:     []string{"0x0000000000000000000000000000000000000000"},
			},
			Address: make([]byte, 20),
		},
	}, nil, nil
}

func NewStubQuorumValidator() *ValidatorStub {
	return &ValidatorStub{}
}
