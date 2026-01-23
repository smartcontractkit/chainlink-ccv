package verifier_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/ccvstorage"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/lbtc"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/storage"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

// Please see lbtc/attestation.go to see how the CCV data is created and how TokenTransfer.ExtraData is used
// CCVData: <4 byte verifier version><attestation> (set by offchain)
// TokenTransfer.ExtraData: <message_hash> (set by onchain).
const (
	lbtcAttestation = `
		{
			"attestations": [
				{
					"message_hash": "0x1111",
					"attestation": "0x00aa",
					"status": "NOTARIZATION_STATUS_SESSION_APPROVED"
				},
				{
					"message_hash": "0x2222",
					"attestation": "0x00bb",
					"status": "NOTARIZATION_STATUS_SESSION_APPROVED"
				}
			]
		}`
	lbtcAttestationPending = `
		{
			"attestations": [
				{
					"message_hash": "0x1111",
					"attestation": "0xdeadbeef",
					"status": "NOTARIZATION_STATUS_PENDING"
				},
				{
					"message_hash": "0x2222",
					"attestation": "0xdeadbeef",
					"status": "NOTARIZATION_STATUS_PENDING"
				}
			]
		}`
)

func Test_LBTCMessages_Success(t *testing.T) {
	ts := newTestSetup(t)
	t.Cleanup(ts.cleanup)

	destVerifier, err := protocol.RandomAddress()
	require.NoError(t, err)

	extraData1, err := protocol.NewByteSliceFromHex("0x1111")
	require.NoError(t, err)
	extraData2, err := protocol.NewByteSliceFromHex("0x2222")
	require.NoError(t, err)
	// LBTC Verifier Version + attestation payload
	ccvData1, err := protocol.NewByteSliceFromHex("0xf0f3a13500aa")
	require.NoError(t, err)
	ccvData2, err := protocol.NewByteSliceFromHex("0xf0f3a13500bb")
	require.NoError(t, err)

	server := createFakeLBTCServer(t, lbtcAttestation)
	t.Cleanup(server.Close)

	config := createCoordinatorConfig(
		"cctp-verifier",
		map[protocol.ChainSelector]protocol.UnknownAddress{
			chain1337: testCCVAddr,
		})

	mockSetup := verifier.SetupMockSourceReader(t)
	mockSetup.ExpectFetchMessageSentEvent(false)
	sourceReaders := map[protocol.ChainSelector]chainaccess.SourceReader{
		chain1337: mockSetup.Reader,
	}

	lbtcConfig := lbtc.LBTCConfig{
		AttestationAPI:          server.URL,
		AttestationAPITimeout:   1 * time.Minute,
		AttestationAPIInterval:  1 * time.Millisecond,
		AttestationAPIBatchSize: 10,
		ParsedVerifierResolvers: map[protocol.ChainSelector]protocol.UnknownAddress{
			chain1337: testCCVAddr,
			chain2337: destVerifier,
		},
	}

	// Set up mock head tracker
	mockLatestBlocks(mockSetup.Reader)

	inMem := ccvstorage.NewInMemory()
	v, err := createLBTCCoordinator(
		ts,
		&lbtcConfig,
		config,
		sourceReaders,
		inMem,
	)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = v.Close() })

	msg1 := createTestMessageSentEventWithToken(t, 100, chain1337, chain2337, 0, 300_000, 900, &protocol.TokenTransfer{
		ExtraData:       extraData1,
		ExtraDataLength: uint16(len(extraData1)),
	})
	msg2 := createTestMessageSentEventWithToken(t, 200, chain1337, chain2337, 0, 300_000, 901, &protocol.TokenTransfer{
		ExtraData:       extraData2,
		ExtraDataLength: uint16(len(extraData2)),
	})
	testEvents := []protocol.MessageSentEvent{msg1, msg2}

	var messagesSent atomic.Int32
	sendEventsAsync(testEvents, mockSetup.Channel, &messagesSent, 10*time.Millisecond)

	var results map[protocol.Bytes32]protocol.VerifierResult
	require.Eventually(t, func() bool {
		reader := storage.NewAttestationCCVReader(inMem)
		results, err = reader.GetVerifications(
			t.Context(),
			[]protocol.Bytes32{msg1.MessageID, msg2.MessageID},
		)
		if err != nil {
			return false
		}
		return len(results) == 2
	}, tests.WaitTimeout(t), 500*time.Millisecond, "waiting for messages to land in ccv storage")

	assertResultMatchesMessage(t, results[msg1.MessageID], msg1, ccvData1, testCCVAddr, destVerifier)
	assertResultMatchesMessage(t, results[msg2.MessageID], msg2, ccvData2, testCCVAddr, destVerifier)
}

func Test_LBTCMessages_RetryingAttestation(t *testing.T) {
	ts := newTestSetup(t)
	t.Cleanup(ts.cleanup)

	destVerifier, err := protocol.RandomAddress()
	require.NoError(t, err)

	extraData1, err := protocol.NewByteSliceFromHex("0x1111")
	require.NoError(t, err)
	extraData2, err := protocol.NewByteSliceFromHex("0x2222")
	require.NoError(t, err)
	// LBTC Verifier Version + attestation payload
	ccvData1, err := protocol.NewByteSliceFromHex("0xf0f3a13500aa")
	require.NoError(t, err)
	ccvData2, err := protocol.NewByteSliceFromHex("0xf0f3a13500bb")
	require.NoError(t, err)

	// This server will return a pending attestation twice, then a completed one
	var requestCounter atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestCounter.Load() >= 2 {
			_, err := w.Write([]byte(lbtcAttestation))
			require.NoError(t, err)
			return
		}

		_, err := w.Write([]byte(lbtcAttestationPending))
		requestCounter.Add(1)
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	config := createCoordinatorConfig(
		"cctp-verifier",
		map[protocol.ChainSelector]protocol.UnknownAddress{
			chain1337: testCCVAddr,
		})

	mockSetup := verifier.SetupMockSourceReader(t)
	mockSetup.ExpectFetchMessageSentEvent(false)
	sourceReaders := map[protocol.ChainSelector]chainaccess.SourceReader{
		chain1337: mockSetup.Reader,
	}

	lbtcConfig := lbtc.LBTCConfig{
		AttestationAPI:          server.URL,
		AttestationAPITimeout:   1 * time.Minute,
		AttestationAPIInterval:  1 * time.Millisecond,
		AttestationAPIBatchSize: 10,
		ParsedVerifierResolvers: map[protocol.ChainSelector]protocol.UnknownAddress{
			chain1337: testCCVAddr,
			chain2337: destVerifier,
		},
	}

	// Set up mock head tracker
	mockLatestBlocks(mockSetup.Reader)

	inMem := ccvstorage.NewInMemory()
	v, err := createLBTCCoordinator(
		ts,
		&lbtcConfig,
		config,
		sourceReaders,
		inMem,
	)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = v.Close() })

	msg1 := createTestMessageSentEventWithToken(t, 100, chain1337, chain2337, 0, 300_000, 900, &protocol.TokenTransfer{
		ExtraData:       extraData1,
		ExtraDataLength: uint16(len(extraData1)),
	})
	msg2 := createTestMessageSentEventWithToken(t, 200, chain1337, chain2337, 0, 300_000, 901, &protocol.TokenTransfer{
		ExtraData:       extraData2,
		ExtraDataLength: uint16(len(extraData2)),
	})
	testEvents := []protocol.MessageSentEvent{msg1, msg2}

	var messagesSent atomic.Int32
	sendEventsAsync(testEvents, mockSetup.Channel, &messagesSent, 10*time.Millisecond)

	var results map[protocol.Bytes32]protocol.VerifierResult
	require.Eventually(t, func() bool {
		reader := storage.NewAttestationCCVReader(inMem)
		results, err = reader.GetVerifications(
			t.Context(),
			[]protocol.Bytes32{msg1.MessageID, msg2.MessageID},
		)
		if err != nil {
			return false
		}
		return len(results) == 2
	}, tests.WaitTimeout(t), 200*time.Millisecond, "waiting for messages to land in ccv storage")

	assertResultMatchesMessage(t, results[msg1.MessageID], msg1, ccvData1, testCCVAddr, destVerifier)
	assertResultMatchesMessage(t, results[msg2.MessageID], msg2, ccvData2, testCCVAddr, destVerifier)
}

func createLBTCCoordinator(
	ts *testSetup,
	lbtcConfig *lbtc.LBTCConfig,
	config verifier.CoordinatorConfig,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	inMemStorage *ccvstorage.InMemoryCCVStorage,
) (*verifier.Coordinator, error) {
	noopMonitoring := monitoring.NewFakeVerifierMonitoring()
	noopLatencyTracker := verifier.NoopLatencyTracker{}

	attestationService, err := lbtc.NewAttestationService(ts.logger, *lbtcConfig)
	require.NoError(ts.t, err)

	ccvWriter := storage.NewAttestationCCVWriter(
		ts.logger,
		lbtcConfig.ParsedVerifierResolvers,
		inMemStorage,
	)

	return verifier.NewCoordinator(
		ts.ctx,
		ts.logger,
		lbtc.NewVerifierWithConfig(ts.logger, attestationService, lbtc.VerifierVersion, 100*time.Millisecond, 100*time.Millisecond),
		sourceReaders,
		ccvWriter,
		config,
		noopLatencyTracker,
		noopMonitoring,
		ts.chainStatusManager,
	)
}

func createFakeLBTCServer(t *testing.T, response string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bridge/v1/deposits/getByHash" {
			_, err := w.Write([]byte(response))
			require.NoError(t, err)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
}
