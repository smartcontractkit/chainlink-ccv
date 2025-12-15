package verifier_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/cctp"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/storage"
)

var (
	chain1337 = protocol.ChainSelector(chainsel.GETH_TESTNET.Selector)
	chain2337 = protocol.ChainSelector(chainsel.GETH_DEVNET_2.Selector)
)

var attestation1 = `
{
  "messages": [
	{
      "message": "0xcccccc22",
      "eventNonce": "9681",
      "attestation": "0xaaaaaa22",
      "decodedMessage": {
        "sourceDomain": "100",
        "destinationDomain": "101",
        "nonce": "569",
        "sender": "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
        "recipient": "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
        "destinationCaller": "0xf2Edb1Ad445C6abb1260049AcDDCA9E84D7D8aaA",
        "messageBody": "0x00000000000000050000000300000000000194c2a65fc943419a5ad590042fd67c9791fd015acf53a54cc823edb8ff81b9ed722e00000000000000000000000019330d10d9cc8751218eaf51e8885d058642e08a000000000000000000000000fc05ad74c6fe2e7046e091d6ad4f660d2a15976200000000c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d610000000000000000000000002d475f4746419c83be23056309a8e2ac33b30e3b0000000000000000000000000000000000000000000000000000000002b67df0feae5e08f5e6bf04d8c1de7dada9235c56996f4420b14371d6c6f3ddd2f2da78",
        "decodedMessageBody": {
          "burnToken": "0x4Bc078D75390C0f5CCc3e7f59Ae2159557C5eb85",
          "mintRecipient": "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
          "amount": "5000",
          "messageSender": "0x1100000000000000000000000000000000000000",
          "hookData": "0x8e1d1a9d42fdceb59007e3a5aee1f4a6b2d92f2922e5ae879257aaea310aae61bf1bb993"
        }
      },
      "cctpVersion": "2",
      "status": "complete"
    }
  ]
}`

var attestation2 = `
{
  "messages": [
    {
      "message": "0xbbbbbb22",
      "eventNonce": "9682",
      "attestation": "0xaaaaaa11",
      "decodedMessage": {
        "sourceDomain": "100",
        "destinationDomain": "101",
        "nonce": "570",
        "sender": "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
        "recipient": "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
        "destinationCaller": "0xf2Edb1Ad445C6abb1260049AcDDCA9E84D7D8aaA",
        "messageBody": "0x00000000000000050000000300000000000194c2a65fc943419a5ad590042fd67c9791fd015acf53a54cc823edb8ff81b9ed722e00000000000000000000000019330d10d9cc8751218eaf51e8885d058642e08a000000000000000000000000fc05ad74c6fe2e7046e091d6ad4f660d2a15976200000000c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d610000000000000000000000002d475f4746419c83be23056309a8e2ac33b30e3b0000000000000000000000000000000000000000000000000000000002b67df0feae5e08f5e6bf04d8c1de7dada9235c56996f4420b14371d6c6f3ddd2f2da78",
        "decodedMessageBody": {
          "burnToken": "0x4Bc078D75390C0f5CCc3e7f59Ae2159557C5eb85",
          "mintRecipient": "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
          "amount": "5000",
          "messageSender": "0x1100000000000000000000000000000000000000",
          "hookData": "0x8e1d1a9da912928643f3adf7fefe08dcbc40a1ca831ee861de1d65cca2c6e8a1a2bcda7a"
        }
      },
      "cctpVersion": "2",
      "status": "complete"
    }
  ]
}
`

var attestation3 = `
{
  "messages": [
    {
      "message": "0xbbbbbb55",
      "eventNonce": "9682",
      "attestation": "0xaaaaaa55",
      "decodedMessage": {
        "sourceDomain": "101",
        "destinationDomain": "100",
        "nonce": "570",
        "sender": "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
        "recipient": "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
        "destinationCaller": "0xf2Edb1Ad445C6abb1260049AcDDCA9E84D7D8aaA",
        "messageBody": "0x00000000000000050000000300000000000194c2a65fc943419a5ad590042fd67c9791fd015acf53a54cc823edb8ff81b9ed722e00000000000000000000000019330d10d9cc8751218eaf51e8885d058642e08a000000000000000000000000fc05ad74c6fe2e7046e091d6ad4f660d2a15976200000000c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d610000000000000000000000002d475f4746419c83be23056309a8e2ac33b30e3b0000000000000000000000000000000000000000000000000000000002b67df0feae5e08f5e6bf04d8c1de7dada9235c56996f4420b14371d6c6f3ddd2f2da78",
        "decodedMessageBody": {
          "burnToken": "0x4Bc078D75390C0f5CCc3e7f59Ae2159557C5eb85",
          "mintRecipient": "0xb7317b4EFEa194a22bEB42506065D3772C2E95EF",
          "amount": "5000",
          "messageSender": "0x2222222200000000000000000000000000000000",
          "hookData": "0x8e1d1a9d78bd0517e2f4167315be5921f215f8d12d8ba1b91d7884ec7fced62d1123f943"
        }
      },
      "cctpVersion": "2",
      "status": "complete"
    }
  ]
}
`

func Test_CCTPMessages_SingleSource(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.cleanup()

	txHash1, err := protocol.NewByteSliceFromHex("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	require.NoError(t, err)
	txHash2, err := protocol.NewByteSliceFromHex("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	require.NoError(t, err)

	attestationResponse := []attestationMock{
		{100, txHash1, attestation1},
		{100, txHash2, attestation2},
	}

	destVerifier, err := protocol.RandomAddress()
	require.NoError(t, err)

	// Version + encoded msgs + attestation
	ccvData1, err := protocol.NewByteSliceFromHex("0x8e1d1a9dcccccc22aaaaaa22")
	require.NoError(t, err)
	ccvData2, err := protocol.NewByteSliceFromHex("0x8e1d1a9dbbbbbb22aaaaaa11")
	require.NoError(t, err)

	server := createFakeHTTPServer(t, attestationResponse)
	defer server.Close()

	config := createCoordinatorConfig(
		"cctp-verifier",
		map[protocol.ChainSelector]protocol.UnknownAddress{
			chain1337: testCCVAddr,
		})

	// Set up mock source readerService
	mockSetup := verifier.SetupMockSourceReader(t)
	mockSetup.ExpectFetchMessageSentEvent(false)
	sourceReaders := map[protocol.ChainSelector]chainaccess.SourceReader{
		chain1337: mockSetup.Reader,
	}

	cctpConfig := cctp.CCTPConfig{
		AttestationAPI:         server.URL,
		AttestationAPITimeout:  1 * time.Minute,
		AttestationAPICooldown: 1 * time.Second,
		AttestationAPIInterval: 1 * time.Millisecond,
		ParsedVerifiers: map[protocol.ChainSelector]protocol.UnknownAddress{
			chain1337: testCCVAddr,
			chain2337: destVerifier,
		},
	}

	// Set up mock head tracker
	mockLatestBlocks(mockSetup.Reader)

	inMem := storage.NewInMemory()
	v, err := createCCTPCoordinator(
		ts,
		&cctpConfig,
		config,
		sourceReaders,
		inMem,
	)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// MessageSent IDs are hardcoded to match attestation hookData values, thus asserts on MessageIDs
	msg1 := createTestMessageSentEvent(t, 100, chain1337, chain2337, 0, 300_000, 900)
	msg1.TxHash = txHash1
	require.Equal(t, "0x42fdceb59007e3a5aee1f4a6b2d92f2922e5ae879257aaea310aae61bf1bb993", msg1.MessageID.String())

	msg2 := createTestMessageSentEvent(t, 200, chain1337, chain2337, 0, 300_000, 901)
	msg2.TxHash = txHash2
	require.Equal(t, "0xa912928643f3adf7fefe08dcbc40a1ca831ee861de1d65cca2c6e8a1a2bcda7a", msg2.MessageID.String())
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
	}, 10*time.Second, 500*time.Millisecond, "waiting for messages to land in ccv storage")

	err = v.Close()
	require.NoError(t, err)

	assertResultMatchesMessage(t, results[msg1.MessageID], msg1, ccvData1, testCCVAddr, destVerifier)
	assertResultMatchesMessage(t, results[msg2.MessageID], msg2, ccvData2, testCCVAddr, destVerifier)
}

func Test_CCTPMessages_MultipleSources(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.cleanup()

	txHash1, err := protocol.NewByteSliceFromHex("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	require.NoError(t, err)
	txHash3, err := protocol.NewByteSliceFromHex("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	require.NoError(t, err)

	attestationResponse := []attestationMock{
		{100, txHash1, attestation1},
		{101, txHash3, attestation3},
	}

	destVerifier, err := protocol.NewUnknownAddressFromHex("0x2222222200000000000000000000000000000000")
	require.NoError(t, err)

	// Version + encoded msgs + attestation
	ccvData1, err := protocol.NewByteSliceFromHex("0x8e1d1a9dcccccc22aaaaaa22")
	require.NoError(t, err)
	ccvData2, err := protocol.NewByteSliceFromHex("0x8e1d1a9dbbbbbb55aaaaaa55")
	require.NoError(t, err)

	server := createFakeHTTPServer(t, attestationResponse)
	defer server.Close()

	config := createCoordinatorConfig(
		"cctp-verifier",
		map[protocol.ChainSelector]protocol.UnknownAddress{
			chain1337: testCCVAddr,
			chain2337: destVerifier,
		})

	// Set up mock source readerService
	reader1337 := verifier.SetupMockSourceReader(t)
	reader1337.ExpectFetchMessageSentEvent(false)

	reader2337 := verifier.SetupMockSourceReader(t)
	reader2337.ExpectFetchMessageSentEvent(false)
	sourceReaders := map[protocol.ChainSelector]chainaccess.SourceReader{
		chain1337: reader1337.Reader,
		chain2337: reader2337.Reader,
	}

	cctpConfig := cctp.CCTPConfig{
		AttestationAPI:         server.URL,
		AttestationAPITimeout:  1 * time.Minute,
		AttestationAPICooldown: 1 * time.Second,
		AttestationAPIInterval: 1 * time.Millisecond,
		ParsedVerifiers: map[protocol.ChainSelector]protocol.UnknownAddress{
			chain1337: testCCVAddr,
			chain2337: destVerifier,
		},
	}

	// Set up mock head tracker
	mockLatestBlocks(reader1337.Reader)
	mockLatestBlocks(reader2337.Reader)

	inMem := storage.NewInMemory()
	v, err := createCCTPCoordinator(
		ts,
		&cctpConfig,
		config,
		sourceReaders,
		inMem,
	)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// MessageSent IDs are hardcoded to match attestation hookData values, thus asserts on MessageIDs
	msg1337 := createTestMessageSentEvent(t, 100, chain1337, chain2337, 0, 300_000, 900)
	msg1337.TxHash = txHash1
	msg1337.Receipts[0].Issuer = testCCVAddr
	require.Equal(t, "0x42fdceb59007e3a5aee1f4a6b2d92f2922e5ae879257aaea310aae61bf1bb993", msg1337.MessageID.String())

	msg2337 := createTestMessageSentEvent(t, 100, chain2337, chain1337, 0, 300_000, 900)
	msg2337.TxHash = txHash3
	msg2337.Receipts[0].Issuer = destVerifier
	require.Equal(t, "0x78bd0517e2f4167315be5921f215f8d12d8ba1b91d7884ec7fced62d1123f943", msg2337.MessageID.String())

	var sent1337 atomic.Int32
	var sent2337 atomic.Int32
	sendEventsAsync([]protocol.MessageSentEvent{msg1337}, reader1337.Channel, &sent1337, 10*time.Millisecond)
	sendEventsAsync([]protocol.MessageSentEvent{msg2337}, reader2337.Channel, &sent2337, 10*time.Millisecond)

	var results map[protocol.Bytes32]protocol.VerifierResult
	require.Eventually(t, func() bool {
		reader := storage.NewAttestationCCVReader(inMem)
		results, err = reader.GetVerifications(
			t.Context(),
			[]protocol.Bytes32{msg1337.MessageID, msg2337.MessageID},
		)
		if err != nil {
			return false
		}
		return len(results) == 2
	}, 10*time.Second, 500*time.Millisecond, "waiting for messages to land in ccv storage")

	err = v.Close()
	require.NoError(t, err)

	assertResultMatchesMessage(t, results[msg1337.MessageID], msg1337, ccvData1, testCCVAddr, destVerifier)
	assertResultMatchesMessage(t, results[msg2337.MessageID], msg2337, ccvData2, destVerifier, testCCVAddr)
}

func assertResultMatchesMessage(
	t *testing.T,
	result protocol.VerifierResult,
	msg protocol.MessageSentEvent,
	ccvData protocol.ByteSlice,
	sourceCCVAddress protocol.UnknownAddress,
	destCCVAddress protocol.UnknownAddress,
) {
	assert.Equal(t, msg.MessageID.String(), result.MessageID.String())
	assert.Len(t, result.MessageCCVAddresses, 1)
	assert.Equal(t, sourceCCVAddress, result.MessageCCVAddresses[0])
	assert.Equal(t, sourceCCVAddress, result.VerifierSourceAddress)
	assert.Equal(t, destCCVAddress, result.VerifierDestAddress)
	assert.Equal(t, msg.Message, result.Message)
	assert.Equal(t, ccvData, result.CCVData)
}

func createCCTPCoordinator(
	ts *testSetup,
	cctpConfig *cctp.CCTPConfig,
	config verifier.CoordinatorConfig,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	inMemStorage *storage.InMemory,
) (*verifier.Coordinator, error) {
	noopMonitoring := monitoring.NewFakeVerifierMonitoring()
	noopLatencyTracker := verifier.NoopLatencyTracker{}

	attestationService, err := cctp.NewAttestationService(ts.logger, *cctpConfig)
	require.NoError(ts.t, err)

	ccvWriter := storage.NewAttestationCCVWriter(
		ts.logger,
		cctpConfig.ParsedVerifiers,
		inMemStorage,
	)

	return verifier.NewCoordinator(
		ts.logger,
		cctp.NewVerifier(ts.logger, attestationService),
		sourceReaders,
		ccvWriter,
		config,
		noopLatencyTracker,
		noopMonitoring,
		ts.chainStatusManager,
	)
}

type attestationMock struct {
	domainID int
	txHash   protocol.ByteSlice
	response string
}

func createFakeHTTPServer(t *testing.T, attestations []attestationMock) *httptest.Server {
	supportedUrls := make(map[string]string)
	for _, a := range attestations {
		url := fmt.Sprintf("/v2/messages/%d?transactionHash=%s", a.domainID, a.txHash.String())
		supportedUrls[url] = a.response
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if response, exists := supportedUrls[r.URL.Path]; exists {
			_, err := w.Write([]byte(response))
			require.NoError(t, err)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}
