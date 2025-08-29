package aggregation

import "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"

type AggregatorStub struct {
}

func (c *AggregatorStub) CheckAggregation(committee_id string, messageID model.MessageID) {}
