package monitoring

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func Test_MessageLatency(t *testing.T) {
	message1 := generateMessage(t)
	message2 := generateMessage(t)
	message3 := generateMessage(t)

	twoSeconds := time.Now().Add(time.Second * 2)
	tenMinutes := time.Now().Add(time.Minute * 10)

	tests := []struct {
		name              string
		tasks             []verifier.VerificationTask
		messages          []protocol.CCVData
		expectedLatencies []E2ELatencyCall
	}{
		{
			name: "messages with firstSeenAt are tracked correctly",
			tasks: []verifier.VerificationTask{
				{Message: message1, FirstSeenAt: twoSeconds},
				{Message: message2, FirstSeenAt: tenMinutes},
			},
			messages: []protocol.CCVData{
				messageToCCVData(message1),
				messageToCCVData(message2),
			},
			expectedLatencies: []E2ELatencyCall{
				{
					Labels:  []string{"source_chain", message1.SourceChainSelector.String(), "verifier_id", "verifier-1"},
					Latency: time.Since(twoSeconds),
				},
				{
					Labels:  []string{"source_chain", message2.SourceChainSelector.String(), "verifier_id", "verifier-1"},
					Latency: time.Since(tenMinutes),
				},
			},
		},
		{
			name: "messages without firstSeenAt are tracked as they just happened",
			tasks: []verifier.VerificationTask{
				{Message: message1},
			},
			messages: []protocol.CCVData{
				messageToCCVData(message1),
			},
			expectedLatencies: []E2ELatencyCall{
				{
					Labels:  []string{"source_chain", message1.SourceChainSelector.String(), "verifier_id", "verifier-1"},
					Latency: time.Since(time.Now()),
				},
			},
		},
		{
			name: "messages not marked as seen are ignored",
			tasks: []verifier.VerificationTask{
				{Message: message1, FirstSeenAt: twoSeconds},
			},
			messages: []protocol.CCVData{
				messageToCCVData(message2),
				messageToCCVData(message3),
			},
			expectedLatencies: []E2ELatencyCall{},
		},
		{
			name: "latencies are tracked once even if message appears the same with different seenAt",
			tasks: []verifier.VerificationTask{
				{Message: message1, FirstSeenAt: twoSeconds},
				{Message: message1, FirstSeenAt: tenMinutes},
			},
			messages: []protocol.CCVData{
				messageToCCVData(message1),
			},
			expectedLatencies: []E2ELatencyCall{
				{
					Labels:  []string{"source_chain", message1.SourceChainSelector.String(), "verifier_id", "verifier-1"},
					Latency: time.Since(twoSeconds),
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lggr := logger.Test(t)
			monitoring := NewFakeVerifierMonitoring()
			tracker := NewMessageLatencyTracker(lggr, "verifier-1", monitoring)

			for i := range tc.tasks {
				tracker.MarkMessageAsSeen(&tc.tasks[i])
			}

			ctx := context.Background()
			tracker.TrackMessageLatencies(ctx, tc.messages)
			calls := monitoring.Fake.E2ELatencyCalls

			require.Equal(t, len(tc.expectedLatencies), len(calls))

			for i, expected := range tc.expectedLatencies {
				actual := calls[i]
				assert.Equal(t, expected.Labels, actual.Labels)
				// Allow some leeway in latency comparison due to execution time
				assert.InDelta(t,
					expected.Latency.Seconds(),
					actual.Latency.Seconds(),
					1.0,
				)
			}
		})
	}
}

func Test_UnderlyingCacheTTL(t *testing.T) {
	lggr := logger.Test(t)
	monitoring := NewFakeVerifierMonitoring()
	tracker := &inmemoryMessageLatencyTracker{
		lggr:       lggr,
		verifierID: "verifier-ttl-test",
		monitoring: monitoring,
		messageTimestamps: cache.New(
			1*time.Nanosecond,
			1*time.Nanosecond,
		),
	}

	message := generateMessage(t)
	task := verifier.VerificationTask{
		Message:     message,
		FirstSeenAt: time.Now(),
	}

	tracker.MarkMessageAsSeen(&task)
	time.Sleep(100 * time.Millisecond)

	tracker.TrackMessageLatencies(context.Background(), []protocol.CCVData{
		messageToCCVData(message),
	})

	require.Len(t, monitoring.Fake.E2ELatencyCalls, 0)
}

func generateMessage(t *testing.T) protocol.Message {
	generateRandomUint64 := func(t *testing.T) uint64 {
		var buf [8]byte
		_, err := rand.Read(buf[:])
		require.NoError(t, err)
		return binary.BigEndian.Uint64(buf[:])
	}

	return protocol.Message{
		SourceChainSelector: protocol.ChainSelector(generateRandomUint64(t)),
		DestChainSelector:   protocol.ChainSelector(generateRandomUint64(t)),
	}
}

func messageToCCVData(msg protocol.Message) protocol.CCVData {
	return protocol.CCVData{
		Message:             msg,
		MessageID:           msg.MustMessageID(),
		SourceChainSelector: msg.SourceChainSelector,
	}
}
