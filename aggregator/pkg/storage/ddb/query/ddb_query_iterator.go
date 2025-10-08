// file: ddb/query_iterator.go
package query

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
)

// DynamoDBQuerier is the tiny surface we need for mocking with mockery.
//
//go:generate mockery --name DynamoDBQuerier --output ./mocks --outpkg mocks --filename dynamodb_querier_mock.go
type DynamoDBQuerier interface {
	// Query executes a DynamoDB query operation
	Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
}

// Iterator wraps DynamoDB query operations with pagination support.
type Iterator struct {
	client     DynamoDBQuerier // <-- was *dynamodb.Client
	input      *dynamodb.QueryInput
	monitoring common.AggregatorMonitoring

	page    *dynamodb.QueryOutput
	index   int
	current map[string]types.AttributeValue

	err       error
	exhausted bool
}

func NewIterator(client DynamoDBQuerier, input *dynamodb.QueryInput, monitoring common.AggregatorMonitoring) *Iterator {
	cp := types.ReturnConsumedCapacityIndexes
	in := *input
	in.ReturnConsumedCapacity = cp

	return &Iterator{
		client:     client,
		input:      &in,
		monitoring: monitoring,
	}
}

func (it *Iterator) SetPageLimit(limit int32) { it.input.Limit = aws.Int32(limit) }
func (it *Iterator) Err() error               { return it.err }
func (it *Iterator) Item() map[string]types.AttributeValue {
	return it.current
}

// Next advances the iterator to the next item and reports whether one exists.
// When Next returns false, check Err() to distinguish between a clean EOF and an error.
func (it *Iterator) Next(ctx context.Context) bool {
	if it.exhausted || it.err != nil {
		return false
	}

	// If we have a page and more items in it, advance within the page.
	if it.page != nil && it.index < len(it.page.Items) {
		it.current = it.page.Items[it.index]
		it.index++
		return true
	}

	// Need a new page.
	if err := it.fetchNextPage(ctx); err != nil {
		it.err = err
		return false
	}

	if it.exhausted {
		return false
	}

	// If the fetched page has no items, we're exhausted.
	if len(it.page.Items) == 0 {
		it.exhausted = true
		return false
	}

	// Start from the first item on the new page.
	it.index = 1
	it.current = it.page.Items[0]
	return true
}

func (it *Iterator) fetchNextPage(ctx context.Context) error {
	if it.page != nil && it.page.LastEvaluatedKey == nil {
		it.exhausted = true
		return nil
	}
	if it.page != nil && it.page.LastEvaluatedKey != nil {
		it.input.ExclusiveStartKey = it.page.LastEvaluatedKey
	}
	out, err := it.client.Query(ctx, it.input)
	if out != nil && it.monitoring != nil {
		it.monitoring.Metrics().RecordCapacity(out.ConsumedCapacity)
	}
	if err != nil {
		return err
	}
	it.page = out
	it.index = 0
	return nil
}
