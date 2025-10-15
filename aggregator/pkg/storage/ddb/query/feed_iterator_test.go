package query

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/require"

	ddbconstant "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb/constants"
)

const testDay = "2025-09-01"

// ---------- test helpers ----------

func mkRow(day, id string, tsSec int64) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		ddbconstant.FinalizedFeedFieldGSIPK:                               avS(day), // use day as GSIPK in tests
		ddbconstant.FinalizedFeedFieldGSISK:                               avS(id),  // id as GSISK (stable tie-break)
		ddbconstant.FinalizedFeedFieldFinalizedAtVerificationCountSortKey: avN64(tsSec),
		ddbconstant.FinalizedFeedFieldCommitteeIDMessageID:                avS("CID#" + id),
	}
}

// simple slice-backed iterator.
type sliceIter struct {
	items   []map[string]types.AttributeValue
	idx     int
	current map[string]types.AttributeValue
	err     error
}

func (s *sliceIter) Next(ctx context.Context) bool {
	if s.idx >= len(s.items) {
		return false
	}
	s.current = s.items[s.idx]
	s.idx++
	return true
}
func (s *sliceIter) Item() map[string]types.AttributeValue { return s.current }
func (s *sliceIter) Err() error                            { return s.err }

// dataset: day -> shard -> rows
func makeFactory(data map[string]map[string][]map[string]types.AttributeValue) ShardIteratorFactory {
	return func(day, shard string, prev *SinglePartitionPaginationToken) ItemIterator {
		rows := data[day][shard]
		start := 0
		if prev != nil && prev.HasMore && prev.TimeSeqMessage != "" {
			for i := range rows {
				if v, ok := rows[i][ddbconstant.FinalizedFeedFieldGSISK].(*types.AttributeValueMemberS); ok && v.Value == prev.TimeSeqMessage {
					start = i + 1 // exclusive resume
					break
				}
			}
		}
		out := make([]map[string]types.AttributeValue, 0, len(rows)-start)
		out = append(out, rows[start:]...)
		return &sliceIter{items: out}
	}
}

func TestDynamoAggregatedReportFeedIterator_Paginates_NoDupes_NoLoop(t *testing.T) {
	ctx := context.Background()

	day1 := testDay
	day2 := "2025-09-02"
	shards := []string{"s0", "s1"}

	data := map[string]map[string][]map[string]types.AttributeValue{
		day1: {
			"s0": {mkRow(day1, "a1", 1), mkRow(day1, "a3", 5)},
			"s1": {mkRow(day1, "b1", 2), mkRow(day1, "b2", 3), mkRow(day1, "b4", 7)},
		},
		day2: {
			"s0": {mkRow(day2, "c1", 10), mkRow(day2, "c2", 12)},
			"s1": {mkRow(day2, "d1", 11)},
		},
	}

	start := time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC).Unix()
	end := time.Date(2025, 9, 2, 23, 59, 59, 0, time.UTC).Unix()
	minDate := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	pageSize := 2
	var (
		inTok     *AggregatedReportPaginationToken
		collected []string
		safety    = 0
	)

	factory := makeFactory(data)

	for {
		safety++
		require.Less(t, safety, 100, "safety: too many iterations (infinite loop?)")

		di := NewDynamoAggregatedReportFeedIterator(
			start, end, minDate, inTok,
			shards,
			factory,
		)

		emitted := 0
		for emitted < pageSize && di.Next(ctx) {
			id := di.Item()[ddbconstant.FinalizedFeedFieldGSISK].(*types.AttributeValueMemberS).Value
			collected = append(collected, id)
			emitted++
		}
		require.NoError(t, di.Err())

		next := di.NextPageToken()
		if next == nil {
			break
		}
		b, _ := json.Marshal(next)
		inTok = &AggregatedReportPaginationToken{}
		require.NoError(t, json.Unmarshal(b, inTok))
	}

	require.Equal(t, []string{"a1", "b1", "b2", "a3", "b4", "c1", "d1", "c2"}, collected)
}

func TestDynamoAggregatedReportFeedIterator_NoFinalToken_WhenDone(t *testing.T) {
	ctx := context.Background()
	day := testDay
	shards := []string{"s0", "s1"}

	data := map[string]map[string][]map[string]types.AttributeValue{
		day: {
			"s0": {mkRow(day, "a1", 1), mkRow(day, "a2", 3)},
			"s1": {mkRow(day, "b1", 2)},
		},
	}
	start := time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC).Unix()
	end := start + 3600
	minDate := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	pageSize := 2

	var inTok *AggregatedReportPaginationToken
	var out []string

	factory := makeFactory(data)

	// page 1
	di := NewDynamoAggregatedReportFeedIterator(start, end, minDate, inTok, shards, factory)
	emitted := 0
	for emitted < pageSize && di.Next(ctx) {
		id := di.Item()[ddbconstant.FinalizedFeedFieldGSISK].(*types.AttributeValueMemberS).Value
		out = append(out, id)
		emitted++
	}
	require.NoError(t, di.Err())
	next := di.NextPageToken()
	require.NotNil(t, next)

	// page 2 (final)
	di2 := NewDynamoAggregatedReportFeedIterator(start, end, minDate, next, shards, factory)
	emitted = 0
	for emitted < pageSize && di2.Next(ctx) {
		id := di2.Item()[ddbconstant.FinalizedFeedFieldGSISK].(*types.AttributeValueMemberS).Value
		out = append(out, id)
		emitted++
	}
	require.NoError(t, di2.Err())
	next2 := di2.NextPageToken()
	require.Nil(t, next2, "final page should not return a token")

	require.Equal(t, []string{"a1", "b1", "a2"}, out)
}

func TestDynamoAggregatedReportFeedIterator_CarriesCursorsForQuietShards(t *testing.T) {
	ctx := context.Background()
	day := testDay
	shards := []string{"s0", "s1", "s2"}

	// s0 emits first page only; s1 spans pages; s2 emits only on page 2.
	data := map[string]map[string][]map[string]types.AttributeValue{
		day: {
			"s0": {mkRow(day, "a1", 1)},
			"s1": {mkRow(day, "b1", 2), mkRow(day, "b2", 3), mkRow(day, "b3", 4)},
			"s2": {mkRow(day, "c1", 5)},
		},
	}
	start := time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC).Unix()
	end := start + 3600
	minDate := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	pageSize := 2

	factory := makeFactory(data)

	// page 1
	di := NewDynamoAggregatedReportFeedIterator(start, end, minDate, nil, shards, factory)
	emitted := 0
	for emitted < pageSize && di.Next(ctx) {
		emitted++
	}
	require.NoError(t, di.Err())
	tok1 := di.NextPageToken()
	require.NotNil(t, tok1, "token expected after page 1")

	require.Contains(t, tok1.Tokens, "s0")
	require.False(t, tok1.Tokens["s0"].HasMore, "s0 should be exhausted")
	require.Contains(t, tok1.Tokens, "s1")
	require.True(t, tok1.Tokens["s1"].HasMore, "s1 should be pending")

	// page 2: resume and drain
	di2 := NewDynamoAggregatedReportFeedIterator(start, end, minDate, tok1, shards, factory)
	emitted = 0
	var ids []string
	for emitted < pageSize && di2.Next(ctx) {
		id := di2.Item()[ddbconstant.FinalizedFeedFieldGSISK].(*types.AttributeValueMemberS).Value
		ids = append(ids, id)
		emitted++
	}
	require.NoError(t, di2.Err())

	// page 2 should continue s1 (b2,b3). c1 would come after if we asked for more.
	require.Equal(t, []string{"b2", "b3"}, ids)
}
