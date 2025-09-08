package quorum

import (
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
)

type QuorumValidatorStub struct {
	// Add any necessary fields here
}

func (q *QuorumValidatorStub) CheckQuorum(report *model.CommitAggregatedReport) (bool, error) {
	// Implement your quorum checking logic here
	return true, nil
}

func (q *QuorumValidatorStub) ValidateSignature(report *aggregator.MessageWithCCVNodeData) ([]*model.IdentifierSigner, *model.QuorumConfig, error) {
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

func NewStubQuorumValidator() *QuorumValidatorStub {
	return &QuorumValidatorStub{}
}
