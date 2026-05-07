package verifier_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/lombard"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

// Please see lombard/attestation.go to see how the CCV data is created and how TokenTransfer.ExtraData is used
// CCVData: <4 byte verifier version><2 byte rawPayloadLength><rawPayload><2 byte proofLength><proof> (set by offchain)
// TokenTransfer.ExtraData: <message_hash> (set by onchain).
// The attestation from Lombard API is ABI-encoded as abi.encode(bytes, bytes) where first bytes is rawPayload and second bytes is proof.
const (
	// ABI-encoded attestation with rawPayload=0xaa and proof=0xbb.
	lombardAttestation = `
		{
			"attestations": [
				{
					"message_hash": "0x1111",
					"attestation": "0x000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001bb00000000000000000000000000000000000000000000000000000000000000",
					"status": "NOTARIZATION_STATUS_SESSION_APPROVED"
				},
				{
					"message_hash": "0x2222",
					"attestation": "0x000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001cc000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001dd00000000000000000000000000000000000000000000000000000000000000",
					"status": "NOTARIZATION_STATUS_SESSION_APPROVED"
				}
			]
		}`
	lombardAttestationPending = `
		{
			"attestations": [
				{
					"message_hash": "0x1111",
					"attestation": "0x000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001bb00000000000000000000000000000000000000000000000000000000000000",
					"status": "NOTARIZATION_STATUS_PENDING"
				},
				{
					"message_hash": "0x2222",
					"attestation": "0x000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001cc000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001dd00000000000000000000000000000000000000000000000000000000000000",
					"status": "NOTARIZATION_STATUS_PENDING"
				}
			]
		}`
)

func Test_LombardMessages_Success(t *testing.T) {
	ts := newTestSetup(t)
	t.Cleanup(ts.cleanup)

	destVerifier, err := protocol.RandomAddress()
	require.NoError(t, err)

	extraData1, err := protocol.NewByteSliceFromHex("0x1111")
	require.NoError(t, err)
	extraData2, err := protocol.NewByteSliceFromHex("0x2222")
	require.NoError(t, err)
	// Lombard Verifier Version + rawPayloadLength + rawPayload + proofLength + proof
	// Format: [version(4 bytes)][rawPayloadLen(2 bytes)][rawPayload][proofLen(2 bytes)][proof]
	// ccvData1: eba55588 (version) + 0001 (len=1) + aa (payload) + 0001 (len=1) + bb (proof)
	ccvData1, err := protocol.NewByteSliceFromHex("0xeba555880001aa0001bb")
	require.NoError(t, err)
	// ccvData2: eba55588 (version) + 0001 (len=1) + cc (payload) + 0001 (len=1) + dd (proof)
	ccvData2, err := protocol.NewByteSliceFromHex("0xeba555880001cc0001dd")
	require.NoError(t, err)

	server := createFakeLombardServer(t, lombardAttestation)
	t.Cleanup(server.Close)

	config := createCoordinatorConfig(
		"verifier",
		map[protocol.ChainSelector]protocol.UnknownAddress{
			chain1337: testCCVAddr,
		})

	mockSetup := verifier.SetupMockSourceReader(t)
	mockSetup.ExpectFetchMessageSentEvent(false)
	sourceReaders := map[protocol.ChainSelector]chainaccess.SourceReader{
		chain1337: mockSetup.Reader,
	}

	lombardConfig := lombard.LombardConfig{
		AttestationAPI:          server.URL,
		AttestationAPITimeout:   1 * time.Minute,
		AttestationAPIInterval:  1 * time.Millisecond,
		AttestationAPIBatchSize: 10,
		VerifierVersion:         lombard.DefaultVerifierVersion,
		ParsedVerifierResolvers: map[protocol.ChainSelector]protocol.UnknownAddress{
			chain1337: testCCVAddr,
			chain2337: destVerifier,
		},
	}

	// Set up mock head tracker
	mockLatestBlocks(mockSetup.Reader)

	inMem := storage.NewInMemory()
	v, err := createLombardCoordinator(
		ts,
		&lombardConfig,
		config,
		sourceReaders,
		inMem,
	)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = v.Close() })

	// Create messages with token transfers and set the Lombard message hash in the receipt blob
	msg1 := createLombardTestMessage(t, 100, chain1337, chain2337, 900, testCCVAddr, extraData1)
	msg2 := createLombardTestMessage(t, 200, chain1337, chain2337, 901, testCCVAddr, extraData2)
	testEvents := []protocol.MessageSentEvent{msg1, msg2}

	var messagesSent atomic.Int32
	sendEventsAsync(testEvents, mockSetup.Channel, &messagesSent, 10*time.Millisecond)

	var results map[protocol.Bytes32]protocol.VerifierResult
	require.Eventually(t, func() bool {
		reader := storage.NewCCVReader(inMem)
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

func Test_LombardMessages_RetryingAttestation(t *testing.T) {
	ts := newTestSetup(t)
	t.Cleanup(ts.cleanup)

	destVerifier, err := protocol.RandomAddress()
	require.NoError(t, err)

	extraData1, err := protocol.NewByteSliceFromHex("0x1111")
	require.NoError(t, err)
	extraData2, err := protocol.NewByteSliceFromHex("0x2222")
	require.NoError(t, err)
	// Lombard Verifier Version + rawPayloadLength + rawPayload + proofLength + proof
	// Format: [version(4 bytes)][rawPayloadLen(2 bytes)][rawPayload][proofLen(2 bytes)][proof]
	// ccvData1: eba55588 (version) + 0001 (len=1) + aa (payload) + 0001 (len=1) + bb (proof)
	ccvData1, err := protocol.NewByteSliceFromHex("0xeba555880001aa0001bb")
	require.NoError(t, err)
	// ccvData2: eba55588 (version) + 0001 (len=1) + cc (payload) + 0001 (len=1) + dd (proof)
	ccvData2, err := protocol.NewByteSliceFromHex("0xeba555880001cc0001dd")
	require.NoError(t, err)

	// This server will return a pending attestation twice, then a completed one
	var requestCounter atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestCounter.Load() >= 2 {
			_, err := w.Write([]byte(lombardAttestation))
			require.NoError(t, err)
			return
		}

		_, err := w.Write([]byte(lombardAttestationPending))
		requestCounter.Add(1)
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	config := createCoordinatorConfig(
		"verifier",
		map[protocol.ChainSelector]protocol.UnknownAddress{
			chain1337: testCCVAddr,
		})

	mockSetup := verifier.SetupMockSourceReader(t)
	mockSetup.ExpectFetchMessageSentEvent(false)
	sourceReaders := map[protocol.ChainSelector]chainaccess.SourceReader{
		chain1337: mockSetup.Reader,
	}

	lombardConfig := lombard.LombardConfig{
		AttestationAPI:          server.URL,
		AttestationAPITimeout:   1 * time.Minute,
		AttestationAPIInterval:  1 * time.Millisecond,
		AttestationAPIBatchSize: 10,
		VerifierVersion:         lombard.DefaultVerifierVersion,
		ParsedVerifierResolvers: map[protocol.ChainSelector]protocol.UnknownAddress{
			chain1337: testCCVAddr,
			chain2337: destVerifier,
		},
	}

	// Set up mock head tracker
	mockLatestBlocks(mockSetup.Reader)

	inMem := storage.NewInMemory()
	// Use shorter retry intervals for the test to avoid timeouts
	// The test server returns pending attestations twice, then completed ones
	// With 100ms retry delay, this should complete in ~300ms instead of 60+ seconds
	v, err := createLombardCoordinatorWithRetryConfig(
		ts,
		&lombardConfig,
		config,
		sourceReaders,
		inMem,
		100*time.Millisecond, // attestationNotReadyRetry
		100*time.Millisecond, // anyErrorRetry
	)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = v.Close() })

	// Create messages with token transfers and set the Lombard message hash in the receipt blob
	msg1 := createLombardTestMessage(t, 100, chain1337, chain2337, 900, testCCVAddr, extraData1)
	msg2 := createLombardTestMessage(t, 200, chain1337, chain2337, 901, testCCVAddr, extraData2)
	testEvents := []protocol.MessageSentEvent{msg1, msg2}

	var messagesSent atomic.Int32
	sendEventsAsync(testEvents, mockSetup.Channel, &messagesSent, 10*time.Millisecond)

	var results map[protocol.Bytes32]protocol.VerifierResult
	require.Eventually(t, func() bool {
		reader := storage.NewCCVReader(inMem)
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

func createLombardCoordinator(
	ts *testSetup,
	lombardConfig *lombard.LombardConfig,
	config verifier.CoordinatorConfig,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	inMemStorage *storage.InMemoryCCVStorage,
) (*verifier.Coordinator, error) {
	return createLombardCoordinatorWithRetryConfig(
		ts,
		lombardConfig,
		config,
		sourceReaders,
		inMemStorage,
		0, // use default retry intervals
		0,
	)
}

func createLombardCoordinatorWithRetryConfig(
	ts *testSetup,
	lombardConfig *lombard.LombardConfig,
	config verifier.CoordinatorConfig,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	inMemStorage *storage.InMemoryCCVStorage,
	attestationNotReadyRetry time.Duration,
	anyErrorRetry time.Duration,
) (*verifier.Coordinator, error) {
	noopMonitoring := monitoring.NewFakeVerifierMonitoring()
	noopLatencyTracker := testutil.NoopLatencyTracker{}

	attestationService, err := lombard.NewAttestationService(ts.logger, *lombardConfig)
	require.NoError(ts.t, err)

	var lombardVerifier verifier.Verifier
	if attestationNotReadyRetry > 0 || anyErrorRetry > 0 {
		// Use custom retry intervals for tests
		lombardVerifier = lombard.NewVerifierWithConfig(
			ts.logger,
			attestationService,
			lombardConfig.VerifierVersion,
			attestationNotReadyRetry,
			anyErrorRetry,
		)
	} else {
		// Use default retry intervals
		var err error
		lombardVerifier, err = lombard.NewVerifier(ts.logger, *lombardConfig, attestationService)
		require.NoError(ts.t, err)
	}

	ccvWriter := storage.NewCCVWriter(
		ts.logger,
		lombardConfig.ParsedVerifierResolvers,
		inMemStorage,
	)

	return verifier.NewCoordinator(
		ts.logger,
		lombardVerifier,
		sourceReaders,
		ccvWriter,
		config,
		noopLatencyTracker,
		noopMonitoring,
		ts.chainStatusManager,
		heartbeatclient.NewNoopHeartbeatClient(),
		nil,
		ts.db,
	)
}

func createFakeLombardServer(t *testing.T, response string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bridge/v1/deposits/getByHash" {
			_, err := w.Write([]byte(response))
			require.NoError(t, err)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
}

// createLombardTestMessage creates a MessageSentEvent with proper receipt blob structure for Lombard tests.
// The message hash (blob) is placed in the receipt issued by the lombardIssuer (verifier resolver).
func createLombardTestMessage(
	t *testing.T,
	sequenceNumber protocol.SequenceNumber,
	sourceChainSelector, destChainSelector protocol.ChainSelector,
	blockNumber uint64,
	lombardIssuer protocol.UnknownAddress,
	messageHash protocol.ByteSlice,
) protocol.MessageSentEvent {
	t.Helper()
	message := testutil.CreateTestMessage(t, sequenceNumber, sourceChainSelector, destChainSelector, 0, 300_000)
	messageID, _ := message.MessageID()

	executorAddr := make([]byte, 20)
	executorAddr[0] = 0x22 // Must match CreateTestMessage

	routerAddr := make([]byte, 20)
	routerAddr[0] = 0x44

	return protocol.MessageSentEvent{
		MessageID: messageID,
		Message:   message,
		Receipts: []protocol.ReceiptWithBlob{
			{
				// Lombard verifier resolver receipt with the message hash as the blob
				Issuer:            lombardIssuer,
				DestGasLimit:      300000,
				DestBytesOverhead: 100,
				Blob:              messageHash, // This is the key change - message hash goes in the blob
				ExtraArgs:         []byte("test-extra-args"),
			},
			{
				// Executor receipt
				Issuer:            protocol.UnknownAddress(executorAddr),
				DestGasLimit:      0,
				DestBytesOverhead: 0,
				Blob:              []byte{},
				ExtraArgs:         []byte{},
			},
			{
				// Network fee receipt
				Issuer:            protocol.UnknownAddress(routerAddr),
				DestGasLimit:      0,
				DestBytesOverhead: 0,
				Blob:              []byte("router-blob"),
				ExtraArgs:         []byte{},
			},
		},
		BlockNumber: blockNumber,
	}
}
