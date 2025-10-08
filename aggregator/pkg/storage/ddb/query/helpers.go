package query

import (
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	ddbconstant "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb/constants"
)

// Timestamp: FinalizedAt is Unix seconds (N).
func tsFromFinalizedAt(item map[string]types.AttributeValue) (time.Time, error) {
	n, ok := item[ddbconstant.FinalizedFeedFieldFinalizedAt].(*types.AttributeValueMemberN)
	if !ok {
		return time.Time{}, fmt.Errorf("missing or non-numeric %s", ddbconstant.FinalizedFeedFieldFinalizedAt)
	}
	sec, err := strconv.ParseInt(n.Value, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse %s: %w", ddbconstant.FinalizedFeedFieldFinalizedAt, err)
	}
	return time.Unix(sec, 0).UTC(), nil
}

// Tie-break: committeeID#messageID.
func secondaryKeyFromCommitteeMsg(item map[string]types.AttributeValue) (string, error) {
	s, ok := item[ddbconstant.FinalizedFeedFieldCommitteeIDMessageID].(*types.AttributeValueMemberS)
	if !ok {
		return "", fmt.Errorf("missing %s", ddbconstant.FinalizedFeedFieldCommitteeIDMessageID)
	}
	return s.Value, nil
}

// Build a full LastEvaluatedKey (PK/SK + fields we want to carry) from an item.
func itemToKey(item map[string]types.AttributeValue) (map[string]types.AttributeValue, error) {
	pk, ok := item[ddbconstant.FinalizedFeedFieldGSIPK]
	if !ok {
		return nil, fmt.Errorf("missing %s", ddbconstant.FinalizedFeedFieldGSIPK)
	}
	sk, ok := item[ddbconstant.FinalizedFeedFieldGSISK]
	if !ok {
		return nil, fmt.Errorf("missing %s", ddbconstant.FinalizedFeedFieldGSISK)
	}
	return map[string]types.AttributeValue{
		ddbconstant.FinalizedFeedFieldGSIPK:                pk,
		ddbconstant.FinalizedFeedFieldGSISK:                sk,
		ddbconstant.FinalizedFeedFieldCommitteeIDMessageID: item[ddbconstant.FinalizedFeedFieldCommitteeIDMessageID],
		ddbconstant.FinalizedFeedFieldFinalizedAt:          item[ddbconstant.FinalizedFeedFieldFinalizedAt],
	}, nil
}

// Convert LastEvaluatedKey -> pagination token (per shard).
func keyToToken(key map[string]types.AttributeValue) SinglePartitionPaginationToken {
	tok := SinglePartitionPaginationToken{HasMore: true}
	if key == nil {
		tok.HasMore = false
		return tok
	}
	if v, ok := key[ddbconstant.FinalizedFeedFieldCommitteeIDMessageID].(*types.AttributeValueMemberS); ok {
		tok.CommitteeIDMessageID = v.Value
	}
	if v, ok := key[ddbconstant.FinalizedFeedFieldGSIPK].(*types.AttributeValueMemberS); ok {
		tok.DayCommitteePartition = v.Value
	}
	if v, ok := key[ddbconstant.FinalizedFeedFieldFinalizedAt].(*types.AttributeValueMemberN); ok {
		tok.FinalizedAt = v.Value
	}
	if v, ok := key[ddbconstant.FinalizedFeedFieldGSISK].(*types.AttributeValueMemberS); ok {
		tok.TimeSeqMessage = v.Value
	}
	return tok
}
