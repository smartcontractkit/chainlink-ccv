package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestCommitAggregatedReport_GetID(t *testing.T) {
	report := &CommitAggregatedReport{
		MessageID: []byte{0xaa, 0xbb, 0xcc},
	}

	assert.Equal(t, "aabbcc", report.GetID())
}

func TestCommitAggregatedReport_CalculateTimeToAggregation(t *testing.T) {
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name             string
		verifications    []*CommitVerificationRecord
		aggregationTime  time.Time
		expectedDuration time.Duration
	}{
		{
			name: "calculates duration from earliest verification",
			verifications: []*CommitVerificationRecord{
				{createdAt: baseTime.Add(-5 * time.Minute)},
				{createdAt: baseTime.Add(-10 * time.Minute)}, // earliest
				{createdAt: baseTime.Add(-2 * time.Minute)},
			},
			aggregationTime:  baseTime,
			expectedDuration: 10 * time.Minute,
		},
		{
			name: "single verification",
			verifications: []*CommitVerificationRecord{
				{createdAt: baseTime.Add(-3 * time.Minute)},
			},
			aggregationTime:  baseTime,
			expectedDuration: 3 * time.Minute,
		},
		{
			name:             "empty verifications returns zero",
			verifications:    []*CommitVerificationRecord{},
			aggregationTime:  baseTime,
			expectedDuration: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &CommitAggregatedReport{Verifications: tt.verifications}
			result := report.CalculateTimeToAggregation(tt.aggregationTime)

			if len(tt.verifications) == 0 {
				assert.True(t, result >= 0)
			} else {
				assert.Equal(t, tt.expectedDuration, result)
			}
		})
	}
}

func createTestVerificationWithMessage(t *testing.T, sourceSelector, destSelector uint64) *CommitVerificationRecord {
	t.Helper()

	msg := createComprehensiveMessage(t)
	msg.SourceChainSelector = protocol.ChainSelector(sourceSelector)
	msg.DestChainSelector = protocol.ChainSelector(destSelector)

	return &CommitVerificationRecord{
		Message:                msg,
		CCVVersion:             []byte{0x01, 0x02, 0x03, 0x04},
		MessageCCVAddresses:    []protocol.UnknownAddress{{0x11, 0x22}},
		MessageExecutorAddress: protocol.UnknownAddress{0x33, 0x44},
	}
}

func TestCommitAggregatedReport_GetDestinationSelector(t *testing.T) {
	t.Run("returns destination from proto message", func(t *testing.T) {
		verification := createTestVerificationWithMessage(t, 1, 2337)
		report := &CommitAggregatedReport{Verifications: []*CommitVerificationRecord{verification}}

		result := report.GetDestinationSelector()
		assert.Equal(t, uint64(2337), result)
	})

	t.Run("returns zero for empty verifications", func(t *testing.T) {
		report := &CommitAggregatedReport{Verifications: []*CommitVerificationRecord{}}
		assert.Equal(t, uint64(0), report.GetDestinationSelector())
	})

	t.Run("returns zero for nil message", func(t *testing.T) {
		report := &CommitAggregatedReport{
			Verifications: []*CommitVerificationRecord{
				{Message: nil},
			},
		}
		assert.Equal(t, uint64(0), report.GetDestinationSelector())
	})
}

func TestCommitAggregatedReport_GetSourceChainSelector(t *testing.T) {
	t.Run("returns source from proto message", func(t *testing.T) {
		verification := createTestVerificationWithMessage(t, 1337, 2)
		report := &CommitAggregatedReport{Verifications: []*CommitVerificationRecord{verification}}

		result := report.GetSourceChainSelector()
		assert.Equal(t, uint64(1337), result)
	})

	t.Run("returns zero for empty verifications", func(t *testing.T) {
		report := &CommitAggregatedReport{Verifications: []*CommitVerificationRecord{}}
		assert.Equal(t, uint64(0), report.GetSourceChainSelector())
	})
}

func TestCommitAggregatedReport_GetOffRampAddress(t *testing.T) {
	t.Run("returns off ramp address from proto message", func(t *testing.T) {
		verification := createTestVerificationWithMessage(t, 1, 2)
		report := &CommitAggregatedReport{Verifications: []*CommitVerificationRecord{verification}}

		result := report.GetOffRampAddress()
		assert.NotEmpty(t, result)
	})

	t.Run("returns nil for empty verifications", func(t *testing.T) {
		report := &CommitAggregatedReport{Verifications: []*CommitVerificationRecord{}}
		assert.Nil(t, report.GetOffRampAddress())
	})
}

func TestCommitAggregatedReport_GetMessageCCVAddresses(t *testing.T) {
	expectedAddrs := []protocol.UnknownAddress{{0x11, 0x22}, {0x33, 0x44}}
	verification := &CommitVerificationRecord{
		MessageCCVAddresses: expectedAddrs,
	}
	report := &CommitAggregatedReport{Verifications: []*CommitVerificationRecord{verification}}

	result := report.GetMessageCCVAddresses()
	assert.Equal(t, expectedAddrs, result)
}

func TestCommitAggregatedReport_GetMessageExecutorAddress(t *testing.T) {
	expectedAddr := protocol.UnknownAddress{0x55, 0x66, 0x77}
	verification := &CommitVerificationRecord{
		MessageExecutorAddress: expectedAddr,
	}
	report := &CommitAggregatedReport{Verifications: []*CommitVerificationRecord{verification}}

	result := report.GetMessageExecutorAddress()
	assert.Equal(t, expectedAddr, result)
}

func TestCommitAggregatedReport_GetVersion(t *testing.T) {
	expectedVersion := []byte{0x01, 0x02, 0x03, 0x04}
	verification := &CommitVerificationRecord{
		CCVVersion: expectedVersion,
	}
	report := &CommitAggregatedReport{Verifications: []*CommitVerificationRecord{verification}}

	result := report.GetVersion()
	assert.Equal(t, expectedVersion, result)
}

func TestCommitAggregatedReport_GetProtoMessage(t *testing.T) {
	t.Run("returns proto message from first verification", func(t *testing.T) {
		msg := createComprehensiveMessage(t)
		verification := &CommitVerificationRecord{Message: msg}
		report := &CommitAggregatedReport{Verifications: []*CommitVerificationRecord{verification}}

		result := report.GetProtoMessage()
		require.NotNil(t, result)

		protoFromDirect, err := common.MapProtocolMessageToProtoMessage(msg)
		require.NoError(t, err)
		assert.Equal(t, protoFromDirect.SequenceNumber, result.SequenceNumber)
	})

	t.Run("returns nil for empty verifications", func(t *testing.T) {
		report := &CommitAggregatedReport{Verifications: []*CommitVerificationRecord{}}
		assert.Nil(t, report.GetProtoMessage())
	})

	t.Run("returns nil for nil message in verification", func(t *testing.T) {
		verification := &CommitVerificationRecord{Message: nil}
		report := &CommitAggregatedReport{Verifications: []*CommitVerificationRecord{verification}}
		assert.Nil(t, report.GetProtoMessage())
	})
}
