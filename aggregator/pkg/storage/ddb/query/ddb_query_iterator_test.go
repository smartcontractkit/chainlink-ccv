// file: ddb/query_iterator_mockery_test.go
package query

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb/query/mocks"
)

func avS(s string) *types.AttributeValueMemberS { return &types.AttributeValueMemberS{Value: s} }

func TestQueryIterator_PaginatesAndYieldsAllItemsOldestToNewestWithinEachPage(t *testing.T) {
	ctx := context.Background()

	// Page 1: two items and a LastEvaluatedKey -> indicates another page follows
	page1 := &dynamodb.QueryOutput{
		Items: []map[string]types.AttributeValue{
			{"id": avS("a1")},
			{"id": avS("a2")},
		},
		LastEvaluatedKey: map[string]types.AttributeValue{"k": avS("lastEvaluatedKey1")},
		ConsumedCapacity: &types.ConsumedCapacity{CapacityUnits: newFloat64(1)},
	}

	// Page 2: one item, no LastEvaluatedKey -> last page
	page2 := &dynamodb.QueryOutput{
		Items: []map[string]types.AttributeValue{
			{"id": avS("b1")},
		},
		LastEvaluatedKey: nil,
		ConsumedCapacity: &types.ConsumedCapacity{CapacityUnits: newFloat64(2)},
	}

	querier := mocks.NewDynamoDBQuerier(t)
	// Expect two Query calls: first without ExclusiveStartKey, second with it.
	querier.
		On("Query",
			ctx,
			mock.MatchedBy(func(in *dynamodb.QueryInput) bool {
				return in != nil &&
					in.ExclusiveStartKey == nil &&
					in.ReturnConsumedCapacity == types.ReturnConsumedCapacityIndexes
			}),
		).
		Return(page1, nil).
		Once()

	querier.
		On("Query",
			ctx,
			mock.MatchedBy(func(in *dynamodb.QueryInput) bool {
				if in == nil || in.ExclusiveStartKey == nil {
					return false
				}
				v, ok := in.ExclusiveStartKey["k"].(*types.AttributeValueMemberS)
				return ok && v.Value == "lastEvaluatedKey1" &&
					in.ReturnConsumedCapacity == types.ReturnConsumedCapacityIndexes
			}),
		).
		Return(page2, nil).
		Once()

	// Monitor to capture capacity recording
	mon := &monitoring.NoopAggregatorMonitoring{}

	it := NewIterator(querier, &dynamodb.QueryInput{}, mon)

	var got []string
	for it.Next(ctx) {
		got = append(got, it.Item()["id"].(*types.AttributeValueMemberS).Value)
	}
	require.NoError(t, it.Err())
	assert.Equal(t, []string{"a1", "a2", "b1"}, got, "items should arrive in-page order")

	querier.AssertExpectations(t)
}

func TestQueryIterator_PropagatesClientError(t *testing.T) {
	ctx := context.Background()

	querier := mocks.NewDynamoDBQuerier(t)
	querier.
		On("Query",
			ctx,
			mock.MatchedBy(func(in *dynamodb.QueryInput) bool {
				return in != nil &&
					in.ExclusiveStartKey == nil &&
					in.ReturnConsumedCapacity == types.ReturnConsumedCapacityIndexes
			}),
		).
		Return(nil, errors.New("boom")).
		Once()

	it := NewIterator(querier, &dynamodb.QueryInput{}, nil)

	ok := it.Next(ctx)
	assert.False(t, ok)
	assert.Error(t, it.Err())
	querier.AssertExpectations(t)
}

func TestQueryIterator_RespectsSetPageLimit(t *testing.T) {
	ctx := context.Background()

	querier := mocks.NewDynamoDBQuerier(t)
	querier.
		On("Query",
			ctx,
			mock.MatchedBy(func(in *dynamodb.QueryInput) bool {
				return in != nil &&
					in.Limit != nil && *in.Limit == 25 &&
					in.ExclusiveStartKey == nil &&
					in.ReturnConsumedCapacity == types.ReturnConsumedCapacityIndexes
			}),
		).
		Return(&dynamodb.QueryOutput{
			Items: []map[string]types.AttributeValue{},
			// no LastEvaluatedKey -> will exhaust immediately
		}, nil).
		Once()

	it := NewIterator(querier, &dynamodb.QueryInput{}, nil)
	it.SetPageLimit(25)

	assert.False(t, it.Next(ctx)) // empty page => false
	assert.NoError(t, it.Err())
	querier.AssertExpectations(t)
}

// --- helpers ---

func newFloat64(v float64) *float64 { return &v }
