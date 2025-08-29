package model

type QuorumConfig struct {
	fValue       int
	participants []string
}

type CommitAggregatedReport struct {
	MessageID     MessageID
	CommitteeID   string
	Verifications []*CommitVerificationRecord
}

func (c *CommitAggregatedReport) GetDestinationSelector() uint64 {
	return c.Verifications[0].DestChainSelector
}
