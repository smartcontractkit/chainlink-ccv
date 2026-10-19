package protocol

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectCCVsForExecution(t *testing.T) {
	reqAddr, err := RandomAddress()
	require.NoError(t, err)
	optAddrA, err := RandomAddress()
	require.NoError(t, err)
	optAddrB, err := RandomAddress()
	require.NoError(t, err)

	reqResult := VerifierResult{VerifierDestAddress: reqAddr, CCVData: []byte("req"), Timestamp: time.UnixMilli(10)}
	optResultA := VerifierResult{VerifierDestAddress: optAddrA, CCVData: []byte("optA"), Timestamp: time.UnixMilli(5)}
	optResultB := VerifierResult{VerifierDestAddress: optAddrB, CCVData: []byte("optB"), Timestamp: time.UnixMilli(25)}

	byAddr := func(results ...VerifierResult) map[string]VerifierResult {
		m := make(map[string]VerifierResult, len(results))
		for _, r := range results {
			m[r.VerifierDestAddress.String()] = r
		}
		return m
	}

	t.Run("selects required and first threshold-many present optionals in configured order", func(t *testing.T) {
		ccvAddressInfo := CCVAddressInfo{
			RequiredCCVs:      []UnknownAddress{reqAddr},
			OptionalCCVs:      []UnknownAddress{optAddrA, optAddrB},
			OptionalThreshold: 1,
		}

		selected := SelectCCVsForExecution(byAddr(reqResult, optResultA, optResultB), ccvAddressInfo)

		assert.True(t, selected.Complete)
		assert.Nil(t, selected.MissingRequired)
		assert.Equal(t, []VerifierResult{reqResult}, selected.Required)
		// optAddrA precedes optAddrB in configured order, so it's selected
		// even though optAddrB is also present and valid.
		assert.Equal(t, []VerifierResult{optResultA}, selected.Optional)
	})

	t.Run("missing required CCV is reported and selection is incomplete", func(t *testing.T) {
		ccvAddressInfo := CCVAddressInfo{
			RequiredCCVs:      []UnknownAddress{reqAddr},
			OptionalCCVs:      []UnknownAddress{optAddrA},
			OptionalThreshold: 1,
		}

		selected := SelectCCVsForExecution(byAddr(optResultA), ccvAddressInfo)

		assert.False(t, selected.Complete)
		require.NotNil(t, selected.MissingRequired)
		assert.Equal(t, reqAddr.String(), selected.MissingRequired.String())
	})

	t.Run("insufficient optional CCVs leaves selection incomplete", func(t *testing.T) {
		ccvAddressInfo := CCVAddressInfo{
			RequiredCCVs:      []UnknownAddress{reqAddr},
			OptionalCCVs:      []UnknownAddress{optAddrA, optAddrB},
			OptionalThreshold: 2,
		}

		selected := SelectCCVsForExecution(byAddr(reqResult, optResultA), ccvAddressInfo)

		assert.False(t, selected.Complete)
		assert.Nil(t, selected.MissingRequired)
		assert.Equal(t, []VerifierResult{optResultA}, selected.Optional)
	})

	t.Run("zero optional threshold selects no optionals", func(t *testing.T) {
		ccvAddressInfo := CCVAddressInfo{
			RequiredCCVs:      []UnknownAddress{reqAddr},
			OptionalCCVs:      []UnknownAddress{optAddrA, optAddrB},
			OptionalThreshold: 0,
		}

		selected := SelectCCVsForExecution(byAddr(reqResult, optResultA, optResultB), ccvAddressInfo)

		assert.True(t, selected.Complete)
		assert.Empty(t, selected.Optional)
	})

	t.Run("extra present optionals beyond threshold are never selected", func(t *testing.T) {
		ccvAddressInfo := CCVAddressInfo{
			RequiredCCVs:      []UnknownAddress{},
			OptionalCCVs:      []UnknownAddress{optAddrA, optAddrB},
			OptionalThreshold: 1,
		}

		selected := SelectCCVsForExecution(byAddr(optResultA, optResultB), ccvAddressInfo)

		assert.True(t, selected.Complete)
		assert.Len(t, selected.Optional, 1)
		assert.Equal(t, optAddrA.String(), selected.Optional[0].VerifierDestAddress.String())
	})
}
