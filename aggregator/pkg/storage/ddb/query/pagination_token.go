package query

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	ddbconstant "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb/constants"
)

type SinglePartitionPaginationToken struct {
	CommitteeIDMessageID  string `json:"committeeIdMessageId,omitempty"`
	DayCommitteePartition string `json:"dayCommitteePartition,omitempty"`
	FinalizedAt           string `json:"finalizedAt,omitempty"`
	TimeSeqMessage        string `json:"timeSeqMessage,omitempty"`
	HasMore               bool   `json:"hasMore,omitempty"`
}

func (t *SinglePartitionPaginationToken) ToExclusiveStartKey() map[string]types.AttributeValue {
	if t == nil || t.DayCommitteePartition == "" || t.TimeSeqMessage == "" {
		return nil
	}
	return map[string]types.AttributeValue{
		ddbconstant.FinalizedFeedFieldGSIPK:                               &types.AttributeValueMemberS{Value: t.DayCommitteePartition},
		ddbconstant.FinalizedFeedFieldGSISK:                               &types.AttributeValueMemberS{Value: t.TimeSeqMessage},
		ddbconstant.FinalizedFeedFieldCommitteeIDMessageID:                &types.AttributeValueMemberS{Value: t.CommitteeIDMessageID},
		ddbconstant.FinalizedFeedFieldFinalizedAtVerificationCountSortKey: &types.AttributeValueMemberS{Value: t.FinalizedAt},
	}
}

type AggregatedReportPaginationToken struct {
	LastDay string                                    `json:"lastDay,omitempty"`
	Tokens  map[string]SinglePartitionPaginationToken `json:"tokens,omitempty"`
}

func ParsePaginationToken(paginationToken *string) (*AggregatedReportPaginationToken, error) {
	var inTok *AggregatedReportPaginationToken
	if paginationToken != nil && *paginationToken != "" {
		inTok = &AggregatedReportPaginationToken{}
		if err := json.Unmarshal([]byte(*paginationToken), inTok); err != nil {
			return nil, fmt.Errorf("failed to parse pagination token: %w", err)
		}
	}
	return inTok, nil
}

func SerializePaginationToken(token *AggregatedReportPaginationToken) (*string, error) {
	var nextTokenStr *string
	if token != nil {
		b, err := json.Marshal(token)
		if err != nil {
			return nil, err
		}
		tokenStr := string(b)
		nextTokenStr = &tokenStr
	}
	return nextTokenStr, nil
}
