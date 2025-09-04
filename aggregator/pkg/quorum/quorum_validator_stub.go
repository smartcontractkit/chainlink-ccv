package quorum

import "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"

type QuorumValidatorStub struct {
	// Add any necessary fields here
}

func (q *QuorumValidatorStub) CheckQuorum(report *model.CommitAggregatedReport) (bool, error) {
	// Implement your quorum checking logic here
	return true, nil
}

func (q *QuorumValidatorStub) ValidateSignature(report *model.CommitVerificationRecord) (bool, error) {
	// Implement your signature validation logic here
	return true, nil
}
