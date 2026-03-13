package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/lombard"
)

// Lombard Attestation Flow:
//
// 1. The test calls buildLombardAttestation(args) which creates the attestation with a rawPayload
//    that matches LombardVerifier.sol verifyMessage() and _validatePayload():
//    - rawPayload = [versionTag (4 bytes)] + abi.encode(bytes32, uint256, bytes32, address, bytes msgBody)
//    - msgBody = [1 byte padding][destToken 32][sender 32][receiver 32][amount 32][messageId 32] (161 bytes).
//      The contract uses mload(add(msgBody, 0x21)) for token (bytes 1-32), 0x41/0x61/0x81 for sender/recipient/amount.
//    - deliverAndHandle(rawPayload, proof) must return bridgedMessage = versionTag (4) + messageId (32);
//      messageId is at msgBody[129:161].
//
// 2. This attestation is registered with the fake HTTP service via registerLombardAttestation()
//
// 3. The Go verifier fetches the attestation and ToVerifierFormat() prepends the 4-byte version tag.
//
// 4. Final ccvData: [versionTag (4)][rawPayloadLength (2)][rawPayload][proofLength (2)][proof]
//
// 5. LombardVerifier.verifyMessage(..., ccvData) runs _validatePayload(rawPayload, ...) then
//    deliverAndHandle(rawPayload, proof); the mock must return (?, true, versionTag||messageId).
//    The test calls SetLombardMailboxBridgedMessageIfSupported on the destination chain so the mock
//    mailbox returns exactly 36 bytes (avoids InvalidMessageLength 0xc2fdac98).

// SetLombardMailboxBridgedMessageIfSupported writes verifier version + messageID (36 bytes) to the Lombard
// mock mailbox on the given chain (destination). Gets the mailbox via bridge.Mailbox(), then calls
// setMessageId on it. If the chain implements LombardMailboxBridgedMessageSetter (e.g. EVM), this
// runs before building the attestation so deliverAndHandle returns the expected bridged message.
func SetLombardMailboxBridgedMessageIfSupported(ctx context.Context, t *testing.T, destChain cciptestinterfaces.CCIP17, messageID [32]byte) {
	setter, ok := destChain.(cciptestinterfaces.LombardMailboxBridgedMessageSetter)
	if !ok {
		t.Logf("Chain does not implement LombardMailboxBridgedMessageSetter, skipping setMessageId on mailbox")
		return
	}
	err := setter.SetLombardMailboxBridgedMessage(ctx, messageID)
	require.NoError(t, err, "SetLombardMailboxBridgedMessage on destination chain")
}

// registerLombardAttestation registers a Lombard attestation response with the fake service.
func registerLombardAttestation(
	t *testing.T,
	httpUrl string,
	messageHash protocol.ByteSlice,
	attestation string,
	status string,
) {
	reqBody := map[string]string{
		"messageHash": messageHash.String(),
		"attestation": attestation,
		"status":      status,
	}

	reqJSON, err := json.Marshal(reqBody)
	require.NoError(t, err)

	resp, err := http.Post(
		httpUrl+"/lombard/v1/attestations",
		"application/json",
		bytes.NewBuffer(reqJSON),
	)
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Failed to register Lombard attestation")
}

// LombardAttestationArgs holds the message fields required to build a rawPayload that
// passes LombardVerifier.sol _validatePayload and matches what the mock mailbox must return.
type LombardAttestationArgs struct {
	// Sender is the source chain sender address (e.g. 20 bytes EVM), left-padded to 32 in payload.
	Sender []byte
	// DestToken is the destination token address (20 bytes), left-padded to 32.
	DestToken []byte
	// Receiver is the token receiver (e.g. 20 bytes), left-padded to 32.
	Receiver []byte
	// Amount is the token amount (must match message.tokenTransfer[0].amount).
	Amount *big.Int
	// MessageID is the CCIP message ID; contract checks it against bridgedMessage from mailbox.
	MessageID protocol.Bytes32
}

// buildLombardAttestation constructs a Lombard attestation whose rawPayload is compatible with
// LombardVerifier.sol verifyMessage(): _validatePayload(rawPayload, ...) decodes rawPayload[4:]
// as (bytes32, uint256, bytes32, address, bytes msgBody). The contract reads with
// mload(add(msgBody, 0x21)) for token (bytes 1-32 of msgBody data), 0x41 for sender, 0x61 for
// recipient, 0x81 for amount. So we prepend one byte so token is at indices 1-32.
// msgBody = [1 byte][token 32][sender 32][receiver 32][amount 32][messageId 32] = 161 bytes.
func buildLombardAttestation(args LombardAttestationArgs) string {
	versionTag := lombard.DefaultVerifierVersion // VERSION_TAG_V2_0_0 = bytes4(keccak256("LombardVerifier 2.0.0"))

	// Contract uses mload(add(msgBody, 0x21)) for token -> bytes 1-32 of msgBody data (0-indexed: [1:33]).
	// Prepending one byte so token sits at 1-32; sender at 33-64, recipient at 65-96, amount at 97-128, messageId at 129-160.
	msgBody := make([]byte, 161)
	msgBody[0] = 0 // padding so token is at offset 1
	copy(msgBody[1:33], common.LeftPadBytes(args.DestToken, 32))
	copy(msgBody[33:65], common.LeftPadBytes(args.Sender, 32))
	copy(msgBody[65:97], common.LeftPadBytes(args.Receiver, 32))
	if args.Amount == nil {
		args.Amount = new(big.Int)
	}
	args.Amount.FillBytes(msgBody[97:129])
	copy(msgBody[129:161], args.MessageID[:])

	// rawPayload[4:] = abi.encode(bytes32, uint256, bytes32, address, bytes)
	// So rawPayload = [4 byte version tag] + abiEncodedTuple.
	zeroBytes32 := [32]byte{}
	zeroAddr := common.Address{}
	bytes32Type, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		panic("abi bytes32: " + err.Error())
	}
	uint256Type, err := abi.NewType("uint256", "", nil)
	if err != nil {
		panic("abi uint256: " + err.Error())
	}
	addressType, err := abi.NewType("address", "", nil)
	if err != nil {
		panic("abi address: " + err.Error())
	}
	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		panic("abi bytes: " + err.Error())
	}
	packArgs := abi.Arguments{
		{Type: bytes32Type},
		{Type: uint256Type},
		{Type: bytes32Type},
		{Type: addressType},
		{Type: addressType},
		{Type: bytesType},
	}
	packed, err := packArgs.Pack(zeroBytes32, big.NewInt(0), zeroBytes32, zeroAddr, zeroAddr, msgBody)
	if err != nil {
		panic("lombard payload ABI pack: " + err.Error())
	}

	rawPayload := append(append([]byte(nil), versionTag...), packed...)

	proof := []byte{}

	var attestation []byte
	rawPayloadLength := uint16(len(rawPayload))
	attestation = append(attestation, byte(rawPayloadLength>>8), byte(rawPayloadLength))
	attestation = append(attestation, rawPayload...)
	proofLength := uint16(len(proof))
	attestation = append(attestation, byte(proofLength>>8), byte(proofLength))
	attestation = append(attestation, proof...)

	return "0x" + hex.EncodeToString(attestation)
}
