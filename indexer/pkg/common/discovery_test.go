package common_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type stubResolver struct{}

func (s *stubResolver) GetVerifierNameFromAddress(_ protocol.UnknownAddress) string {
	return "test-verifier"
}

func testVerifierResult(messageNumber int) protocol.VerifierResult {
	sourceAddr, _ := protocol.RandomAddress()
	destAddr, _ := protocol.RandomAddress()
	onRampAddr, _ := protocol.RandomAddress()
	offRampAddr, _ := protocol.RandomAddress()
	sender, _ := protocol.RandomAddress()
	receiver, _ := protocol.RandomAddress()

	message := protocol.Message{
		Version:              protocol.MessageVersion,
		SourceChainSelector:  protocol.ChainSelector(1),
		DestChainSelector:    protocol.ChainSelector(2),
		SequenceNumber:       protocol.SequenceNumber(messageNumber),
		OnRampAddressLength:  uint8(len(onRampAddr)),
		OnRampAddress:        onRampAddr,
		OffRampAddressLength: uint8(len(offRampAddr)),
		OffRampAddress:       offRampAddr,
		Finality:             10,
		SenderLength:         uint8(len(sender)),
		Sender:               sender,
		ReceiverLength:       uint8(len(receiver)),
		Receiver:             receiver,
	}

	messageID, _ := message.MessageID()

	return protocol.VerifierResult{
		VerifierSourceAddress:  sourceAddr,
		VerifierDestAddress:    destAddr,
		Message:                message,
		MessageID:              messageID,
		CCVData:                []byte{0x00, 0x01, 0x02, 0x03, 0x04},
		MessageCCVAddresses:    []protocol.UnknownAddress{},
		MessageExecutorAddress: protocol.UnknownAddress{},
		Timestamp:              time.Now(),
	}
}

func TestIsDiscoveryOnly(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "empty ccv data",
			data: []byte{},
			want: true,
		},
		{
			name: "short ccv data",
			data: []byte{0x01, 0x02},
			want: true,
		},
		{
			name: "exactly version length",
			data: protocol.MessageDiscoveryVersion,
			want: true,
		},
		{
			name: "discovery version prefix",
			data: append(protocol.MessageDiscoveryVersion, 0x05, 0x06),
			want: true,
		},
		{
			name: "non-discovery data",
			data: []byte{0x00, 0x01, 0x02, 0x03, 0x04},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vr := protocol.VerifierResult{CCVData: tt.data}
			assert.Equal(t, tt.want, common.IsDiscoveryOnly(vr))
		})
	}
}

func TestConvertDiscoveryResponses(t *testing.T) {
	resolver := &stubResolver{}

	vr1 := testVerifierResult(1)
	vr2 := testVerifierResult(2)

	responses := []protocol.QueryResponse{
		{Data: vr1},
		{Data: vr2},
	}

	messages, persistable, all := common.ConvertDiscoveryResponses(responses, time.Now(), resolver)

	assert.Len(t, messages, 2)
	assert.Len(t, persistable, 2)
	assert.Len(t, all, 2)
}

func TestConvertDiscoveryResponses_SkipsDiscoveryOnly(t *testing.T) {
	resolver := &stubResolver{}

	discoveryOnlyVR := testVerifierResult(1)
	discoveryOnlyVR.CCVData = append(protocol.MessageDiscoveryVersion, 0x05)

	normalVR := testVerifierResult(2)

	responses := []protocol.QueryResponse{
		{Data: discoveryOnlyVR},
		{Data: normalVR},
	}

	messages, persistable, all := common.ConvertDiscoveryResponses(responses, time.Now(), resolver)

	assert.Len(t, messages, 2, "both messages should be discovered")
	assert.Len(t, persistable, 1, "discovery-only verification should be filtered from persistable")
	assert.Len(t, all, 2, "all verifications should be included regardless")
}

func TestConvertDiscoveryResponses_SetsMetadata(t *testing.T) {
	resolver := &stubResolver{}
	now := time.Now()

	vr := testVerifierResult(1)
	responses := []protocol.QueryResponse{{Data: vr}}

	messages, persistable, _ := common.ConvertDiscoveryResponses(responses, now, resolver)

	require.Len(t, messages, 1)
	assert.Equal(t, common.MessageProcessing, messages[0].Metadata.Status)
	assert.Equal(t, now, messages[0].Metadata.IngestionTimestamp)

	require.Len(t, persistable, 1)
	assert.Equal(t, now, persistable[0].Metadata.IngestionTimestamp)
	assert.Equal(t, vr.Timestamp, persistable[0].Metadata.AttestationTimestamp)
	assert.Equal(t, "test-verifier", persistable[0].Metadata.VerifierName)
}
