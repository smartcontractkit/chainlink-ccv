package replay

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// mockReplayStorage implements Storage for testing.
type mockReplayStorage struct {
	mu             sync.Mutex
	messages       []common.MessageWithMetadata
	verifications  []common.VerifierResultWithMetadata
	getCCVDataFunc func(ctx context.Context, messageID protocol.Bytes32) ([]common.VerifierResultWithMetadata, error)
	upsertMsgErr   error
	upsertCCVErr   error
	forceUsed      bool
}

func newMockReplayStorage() *mockReplayStorage {
	return &mockReplayStorage{}
}

func (m *mockReplayStorage) UpsertMessages(_ context.Context, msgs []common.MessageWithMetadata, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.upsertMsgErr != nil {
		return m.upsertMsgErr
	}
	m.messages = append(m.messages, msgs...)
	if force {
		m.forceUsed = true
	}
	return nil
}

func (m *mockReplayStorage) UpsertVerifierResults(_ context.Context, results []common.VerifierResultWithMetadata, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.upsertCCVErr != nil {
		return m.upsertCCVErr
	}
	m.verifications = append(m.verifications, results...)
	if force {
		m.forceUsed = true
	}
	return nil
}

func (m *mockReplayStorage) GetCCVData(ctx context.Context, messageID protocol.Bytes32) ([]common.VerifierResultWithMetadata, error) {
	if m.getCCVDataFunc != nil {
		return m.getCCVDataFunc(ctx, messageID)
	}
	return nil, nil
}

func (m *mockReplayStorage) capturedMessages() []common.MessageWithMetadata {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]common.MessageWithMetadata, len(m.messages))
	copy(cp, m.messages)
	return cp
}

func (m *mockReplayStorage) capturedVerifications() []common.VerifierResultWithMetadata {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]common.VerifierResultWithMetadata, len(m.verifications))
	copy(cp, m.verifications)
	return cp
}

func testVerifierResult(messageNumber int) common.VerifierResultWithMetadata {
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

	return common.VerifierResultWithMetadata{
		VerifierResult: protocol.VerifierResult{
			VerifierSourceAddress:  sourceAddr,
			VerifierDestAddress:    destAddr,
			Message:                message,
			MessageID:              messageID,
			CCVData:                []byte{0x00, 0x01, 0x02, 0x03, 0x04},
			MessageCCVAddresses:    []protocol.UnknownAddress{},
			MessageExecutorAddress: protocol.UnknownAddress{},
			Timestamp:              time.Now(),
		},
		Metadata: common.VerifierResultMetadata{
			AttestationTimestamp: time.Now(),
			IngestionTimestamp:   time.Now(),
		},
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
			assert.Equal(t, tt.want, isDiscoveryOnly(vr))
		})
	}
}

func TestProcessDiscoveryResponses(t *testing.T) {
	lggr := logger.Test(t)
	reg := registry.NewVerifierRegistry()

	engine := &Engine{
		registry: reg,
		lggr:     lggr,
	}

	vr1 := testVerifierResult(1)
	vr2 := testVerifierResult(2)

	responses := []protocol.QueryResponse{
		{Data: vr1.VerifierResult},
		{Data: vr2.VerifierResult},
	}

	messages, verifications := engine.processDiscoveryResponses(responses)

	assert.Len(t, messages, 2)
	assert.Len(t, verifications, 2)
}

func TestProcessDiscoveryResponses_SkipsDiscoveryOnly(t *testing.T) {
	lggr := logger.Test(t)
	reg := registry.NewVerifierRegistry()

	engine := &Engine{
		registry: reg,
		lggr:     lggr,
	}

	discoveryOnlyVR := testVerifierResult(1)
	discoveryOnlyVR.VerifierResult.CCVData = append(protocol.MessageDiscoveryVersion, 0x05)

	normalVR := testVerifierResult(2)

	responses := []protocol.QueryResponse{
		{Data: discoveryOnlyVR.VerifierResult},
		{Data: normalVR.VerifierResult},
	}

	messages, verifications := engine.processDiscoveryResponses(responses)

	assert.Len(t, messages, 2, "both messages should be discovered")
	assert.Len(t, verifications, 1, "discovery-only verification should be filtered out")
}

func TestPersistDiscoveryBatch(t *testing.T) {
	lggr := logger.Test(t)
	store := newMockReplayStorage()
	reg := registry.NewVerifierRegistry()

	engine := &Engine{
		storage:  store,
		registry: reg,
		lggr:     lggr,
	}

	vr := testVerifierResult(1)
	responses := []protocol.QueryResponse{{Data: vr.VerifierResult}}

	messages, verifications := engine.processDiscoveryResponses(responses)

	sinceTS := time.Now().Unix()
	job := &Job{
		ID:                  "test-persist",
		Type:                TypeDiscovery,
		Status:              StatusRunning,
		SinceSequenceNumber: &sinceTS,
	}

	err := engine.persistDiscoveryBatch(context.Background(), job, messages, verifications)
	require.NoError(t, err)

	assert.Len(t, store.capturedMessages(), 1)
	assert.Len(t, store.capturedVerifications(), 1)
}

func TestPersistDiscoveryBatch_ForceFlag(t *testing.T) {
	lggr := logger.Test(t)
	store := newMockReplayStorage()
	reg := registry.NewVerifierRegistry()

	engine := &Engine{
		storage:  store,
		registry: reg,
		lggr:     lggr,
	}

	vr := testVerifierResult(1)
	responses := []protocol.QueryResponse{{Data: vr.VerifierResult}}
	messages, verifications := engine.processDiscoveryResponses(responses)

	sinceTS := time.Now().Unix()
	job := &Job{
		ID:                  "test-force",
		Type:                TypeDiscovery,
		Status:              StatusRunning,
		ForceOverwrite:      true,
		SinceSequenceNumber: &sinceTS,
	}

	err := engine.persistDiscoveryBatch(context.Background(), job, messages, verifications)
	require.NoError(t, err)

	assert.True(t, store.forceUsed, "force flag should be passed to storage")
}

func TestPersistDiscoveryBatch_NoForceByDefault(t *testing.T) {
	lggr := logger.Test(t)
	store := newMockReplayStorage()
	reg := registry.NewVerifierRegistry()

	engine := &Engine{
		storage:  store,
		registry: reg,
		lggr:     lggr,
	}

	vr := testVerifierResult(1)
	responses := []protocol.QueryResponse{{Data: vr.VerifierResult}}
	messages, verifications := engine.processDiscoveryResponses(responses)

	sinceTS := time.Now().Unix()
	job := &Job{
		ID:                  "test-no-force",
		Type:                TypeDiscovery,
		Status:              StatusRunning,
		ForceOverwrite:      false,
		SinceSequenceNumber: &sinceTS,
	}

	err := engine.persistDiscoveryBatch(context.Background(), job, messages, verifications)
	require.NoError(t, err)

	assert.False(t, store.forceUsed, "force flag should not be set for default behavior")
}

func TestGatherAllVerifications_NoCCVAddresses(t *testing.T) {
	lggr := logger.Test(t)
	store := newMockReplayStorage()
	reg := registry.NewVerifierRegistry()

	// Return no CCV addresses for the message
	store.getCCVDataFunc = func(_ context.Context, _ protocol.Bytes32) ([]common.VerifierResultWithMetadata, error) {
		return nil, nil
	}

	engine := &Engine{
		storage:  store,
		registry: reg,
		lggr:     lggr,
	}

	job := &Job{
		ID:     "test-no-addrs",
		Type:   TypeMessages,
		Status: StatusRunning,
	}

	msgID := testVerifierResult(1).VerifierResult.MessageID
	err := engine.gatherAllVerifications(context.Background(), job, msgID)
	require.NoError(t, err)
}

func TestGatherAllVerifications_WithCCVAddressesButNoReaders(t *testing.T) {
	lggr := logger.Test(t)
	store := newMockReplayStorage()
	reg := registry.NewVerifierRegistry()

	verifierAddr, _ := protocol.RandomAddress()
	msgVR := testVerifierResult(1)
	msgVR.VerifierResult.MessageCCVAddresses = []protocol.UnknownAddress{verifierAddr}

	store.getCCVDataFunc = func(_ context.Context, _ protocol.Bytes32) ([]common.VerifierResultWithMetadata, error) {
		return []common.VerifierResultWithMetadata{msgVR}, nil
	}

	engine := &Engine{
		storage:  store,
		registry: reg,
		lggr:     lggr,
	}

	job := &Job{
		ID:     "test-no-readers",
		Type:   TypeMessages,
		Status: StatusRunning,
	}

	err := engine.gatherAllVerifications(context.Background(), job, msgVR.VerifierResult.MessageID)
	require.NoError(t, err)
	assert.Len(t, store.capturedVerifications(), 0)
}

func TestRunDiscoveryReplay_MissingSinceSequenceNumber(t *testing.T) {
	lggr := logger.Test(t)

	engine := &Engine{
		lggr: lggr,
	}

	job := &Job{
		ID:     "test-no-since",
		Type:   TypeDiscovery,
		Status: StatusRunning,
	}

	err := engine.runDiscoveryReplay(context.Background(), job)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "since_sequence_number")
}

func TestRunDiscoveryReplay_MissingFactory(t *testing.T) {
	lggr := logger.Test(t)

	engine := &Engine{
		lggr: lggr,
	}

	sinceTS := time.Now().Unix()
	job := &Job{
		ID:                  "test-no-factory",
		Type:                TypeDiscovery,
		Status:              StatusRunning,
		SinceSequenceNumber: &sinceTS,
	}

	err := engine.runDiscoveryReplay(context.Background(), job)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aggregator reader factory")
}

func TestRunMessageReplay_EmptyMessageIDs(t *testing.T) {
	lggr := logger.Test(t)
	reg := registry.NewVerifierRegistry()

	engine := &Engine{
		registry: reg,
		lggr:     lggr,
	}

	job := &Job{
		ID:         "test-empty-ids",
		Type:       TypeMessages,
		Status:     StatusRunning,
		MessageIDs: []string{},
	}

	err := engine.runMessageReplay(context.Background(), job)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one message ID")
}

func TestRunMessageReplay_NilRegistry(t *testing.T) {
	lggr := logger.Test(t)

	engine := &Engine{
		lggr: lggr,
	}

	job := &Job{
		ID:         "test-nil-reg",
		Type:       TypeMessages,
		Status:     StatusRunning,
		MessageIDs: []string{"0x1234"},
	}

	err := engine.runMessageReplay(context.Background(), job)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verifier registry")
}
