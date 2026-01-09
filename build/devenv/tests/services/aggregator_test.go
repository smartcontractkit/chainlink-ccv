package services_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
	msgdiscoverypb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-discovery/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"

	committee "github.com/smartcontractkit/chainlink-ccv/committee/common"
	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
)

var testCredentials = hmacutil.MustGenerateCredentials()

// generateTestSigningKey generates a deterministic signing key for testing.
func generateTestSigningKey(committeeName string, nodeIndex int) (privateKey, publicKey string, err error) {
	preImage := fmt.Sprintf("dev-private-key-%s-%d-12345678901234567890", committeeName, nodeIndex)
	hash := sha256.Sum256([]byte(preImage))
	privateKey = hex.EncodeToString(hash[:])

	pk, err := commit.ReadPrivateKeyFromString(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to load private key: %w", err)
	}
	_, pubKey, err := commit.NewECDSAMessageSigner(pk)
	if err != nil {
		return "", "", fmt.Errorf("failed to create message signer: %w", err)
	}
	publicKey = pubKey.String()
	return privateKey, publicKey, nil
}

func TestServiceAggregator(t *testing.T) {
	committeeName := "default"
	privateKey, publicKey, err := generateTestSigningKey(committeeName, 0)
	require.NoError(t, err)

	out, err := services.NewAggregator(&services.AggregatorInput{
		CommitteeName:  committeeName,
		Image:          "aggregator:dev",
		HostPort:       8103,
		SourceCodePath: "../../../aggregator",
		RootPath:       "../../../../",
		CommitteeVerifierResolverAddresses: map[uint64]string{
			12922642891491394802: "0x68B1D87F95878fE05B998F19b66F4baba5De1aed",
		},
		DB: &services.AggregatorDBInput{
			Image:    "postgres:16-alpine",
			HostPort: 7432,
		},
		Redis: &services.AggregatorRedisInput{
			Image:    "redis:7-alpine",
			HostPort: 6379,
		},
		Env: &services.AggregatorEnvConfig{
			StorageConnectionURL: fmt.Sprintf("postgresql://%s:%s@default-aggregator-db:5432/%s?sslmode=disable",
				services.DefaultAggregatorDBUsername,
				services.DefaultAggregatorDBPassword,
				services.DefaultAggregatorDBName,
			),
			RedisAddress:  "default-aggregator-redis:6379",
			RedisPassword: "",
			RedisDB:       "0",
		},
		APIClients: []*services.AggregatorClientConfig{{
			ClientID:    "test",
			Description: "Test client",
			Enabled:     true,
			Groups:      []string{},
			APIKeyPairs: []*services.AggregatorAPIKeyPair{{
				APIKey: testCredentials.APIKey,
				Secret: testCredentials.Secret,
			}},
		}},
	}, []*services.VerifierInput{{
		SourceCodePath:   "../../../verifier",
		RootPath:         "../../../../",
		CommitteeName:    committeeName,
		NodeIndex:        0,
		SigningKey:       privateKey,
		SigningKeyPublic: publicKey,
	}})
	require.NoError(t, err)
	t.Run("test #1", func(t *testing.T) {
		_ = out
		// use the data from output, connect HTTP, gRPC clients etc and do the testing
	})
}

// TestAggregatorAuthentication verifies the authentication behavior of the aggregator.
// This test requires a real network connection (not bufconn) because the
// anonymous auth middleware validates peer IP addresses.
func TestServiceAggregatorAuthentication(t *testing.T) {
	committeeName := "auth-test"
	privateKey, publicKey, err := generateTestSigningKey(committeeName, 0)
	require.NoError(t, err)

	grpcHostPort := 50251
	grpcAddress := fmt.Sprintf("localhost:%d", grpcHostPort)

	out, err := services.NewAggregator(&services.AggregatorInput{
		CommitteeName:   committeeName,
		Image:           "aggregator:dev",
		HostPort:        8104,
		ExposedHostPort: grpcHostPort,
		SourceCodePath:  "../../../aggregator",
		RootPath:        "../../../../",
		CommitteeVerifierResolverAddresses: map[uint64]string{
			12922642891491394802: "0x68B1D87F95878fE05B998F19b66F4baba5De1aed",
		},
		DB: &services.AggregatorDBInput{
			Image:    "postgres:16-alpine",
			HostPort: 7433,
		},
		Redis: &services.AggregatorRedisInput{
			Image:    "redis:7-alpine",
			HostPort: 6380,
		},
		Env: &services.AggregatorEnvConfig{
			StorageConnectionURL: fmt.Sprintf("postgresql://%s:%s@auth-test-aggregator-db:5432/%s?sslmode=disable",
				services.DefaultAggregatorDBUsername,
				services.DefaultAggregatorDBPassword,
				services.DefaultAggregatorDBName,
			),
			RedisAddress:  "auth-test-aggregator-redis:6379",
			RedisPassword: "",
			RedisDB:       "0",
		},
		APIClients: []*services.AggregatorClientConfig{
			{
				ClientID:    "test",
				Description: "Test client",
				Enabled:     true,
				Groups:      []string{},
				APIKeyPairs: []*services.AggregatorAPIKeyPair{{
					APIKey: testCredentials.APIKey,
					Secret: testCredentials.Secret,
				}},
			},
		},
	}, []*services.VerifierInput{{
		SourceCodePath:   "../../../verifier",
		RootPath:         "../../../../",
		CommitteeName:    committeeName,
		NodeIndex:        0,
		SigningKey:       privateKey,
		SigningKeyPublic: publicKey,
	}})
	require.NoError(t, err)
	require.NotNil(t, out)

	ctx := context.Background()

	// Connect to aggregator without authentication
	// Use ExternalHTTPUrl which contains host:port accessible from outside Docker
	conn, err := grpc.NewClient(grpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	verifierClient := verifierpb.NewVerifierClient(conn)
	committeeClient := committeepb.NewCommitteeVerifierClient(conn)
	msgDiscoveryClient := msgdiscoverypb.NewMessageDiscoveryClient(conn)

	// Test anonymous authentication for GetVerifierResultsForMessage
	t.Run("GetVerifierResultsForMessage supports anonymous authentication", func(t *testing.T) {
		req := &verifierpb.GetVerifierResultsForMessageRequest{
			MessageIds: [][]byte{{}}, // Single empty message ID
		}

		resp, err := verifierClient.GetVerifierResultsForMessage(ctx, req)
		require.NoError(t, err, "anonymous request should succeed (not return Unauthenticated)")
		require.Len(t, resp.Errors, 1, "should have one error entry")
		st := status.FromProto(resp.Errors[0])
		require.Equal(t, codes.NotFound, st.Code(), "should return NotFound error for the message, not Unauthenticated")
	})

	t.Run("WriteCommitteeVerifierNodeResult requires authentication", func(t *testing.T) {
		req := &committeepb.WriteCommitteeVerifierNodeResultRequest{}

		_, err := committeeClient.WriteCommitteeVerifierNodeResult(ctx, req)
		require.Error(t, err, "unauthenticated request should fail")

		st, ok := status.FromError(err)
		require.True(t, ok, "error should be a gRPC status error")
		require.Equal(t, codes.Unauthenticated, st.Code(), "should return Unauthenticated error")
	})

	t.Run("BatchWriteCommitteeVerifierNodeResult requires authentication", func(t *testing.T) {
		req := &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{}

		_, err := committeeClient.BatchWriteCommitteeVerifierNodeResult(ctx, req)
		require.Error(t, err, "unauthenticated request should fail")

		st, ok := status.FromError(err)
		require.True(t, ok, "error should be a gRPC status error")
		require.Equal(t, codes.Unauthenticated, st.Code(), "should return Unauthenticated error")
	})

	t.Run("ReadCommitteeVerifierNodeResult requires authentication", func(t *testing.T) {
		req := &committeepb.ReadCommitteeVerifierNodeResultRequest{}

		_, err := committeeClient.ReadCommitteeVerifierNodeResult(ctx, req)
		require.Error(t, err, "unauthenticated request should fail")

		st, ok := status.FromError(err)
		require.True(t, ok, "error should be a gRPC status error")
		require.Equal(t, codes.Unauthenticated, st.Code(), "should return Unauthenticated error")
	})

	t.Run("GetMessagesSince requires authentication", func(t *testing.T) {
		req := &msgdiscoverypb.GetMessagesSinceRequest{}

		_, err := msgDiscoveryClient.GetMessagesSince(ctx, req)
		require.Error(t, err, "unauthenticated request should fail")

		st, ok := status.FromError(err)
		require.True(t, ok, "error should be a gRPC status error")
		require.Equal(t, codes.Unauthenticated, st.Code(), "should return Unauthenticated error")
	})
}

// testSigner holds a signing key pair for test scenarios.
type testSigner struct {
	privateKey    *ecdsa.PrivateKey
	privateKeyHex string
	publicKeyHex  string
	address       string
}

// newTestSigner creates a deterministic signer for test scenarios.
func newTestSigner(t *testing.T, committeeName string, nodeIndex int) *testSigner {
	privateKeyHex, publicKeyHex, err := generateTestSigningKey(committeeName, nodeIndex)
	require.NoError(t, err)

	privKeyBytes, err := hex.DecodeString(privateKeyHex)
	require.NoError(t, err)
	privateKey, err := crypto.ToECDSA(privKeyBytes)
	require.NoError(t, err)

	address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	return &testSigner{
		privateKey:    privateKey,
		privateKeyHex: privateKeyHex,
		publicKeyHex:  publicKeyHex,
		address:       address,
	}
}

// aggregatorTestFixture holds the test infrastructure for security test scenarios.
type aggregatorTestFixture struct {
	aggregatorOutput     *services.AggregatorOutput
	honest1Credentials   hmacutil.Credentials
	honest2Credentials   hmacutil.Credentials
	maliciousCredentials hmacutil.Credentials
	honestSigner1        *testSigner
	honestSigner2        *testSigner
	maliciousSigner      *testSigner
	sourceChainSel       uint64
	destChainSel         uint64
	verifierAddress      string
	// Separate clients for each signer
	honest1CommitteeClient   committeepb.CommitteeVerifierClient
	honest2CommitteeClient   committeepb.CommitteeVerifierClient
	maliciousCommitteeClient committeepb.CommitteeVerifierClient
	verifierClient           verifierpb.VerifierClient
	honest1Conn              *grpc.ClientConn
	honest2Conn              *grpc.ClientConn
	maliciousConn            *grpc.ClientConn
	sequenceCounter          uint64
	sequenceCounterMu        sync.Mutex
}

func (f *aggregatorTestFixture) nextSequenceNumber() uint64 {
	f.sequenceCounterMu.Lock()
	defer f.sequenceCounterMu.Unlock()
	f.sequenceCounter++
	return f.sequenceCounter
}

// createValidMessage creates a valid protocol message for testing.
func (f *aggregatorTestFixture) createValidMessage(t *testing.T) *protocol.Message {
	seq := f.nextSequenceNumber()
	executorAddr := make([]byte, 20)
	ccvAddr, err := protocol.NewUnknownAddressFromHex(f.verifierAddress)
	require.NoError(t, err)

	ccvAndExecutorHash, err := protocol.ComputeCCVAndExecutorHash(
		[]protocol.UnknownAddress{ccvAddr},
		protocol.UnknownAddress(executorAddr),
	)
	require.NoError(t, err)

	return &protocol.Message{
		Version:              1,
		SourceChainSelector:  protocol.ChainSelector(f.sourceChainSel),
		DestChainSelector:    protocol.ChainSelector(f.destChainSel),
		SequenceNumber:       protocol.SequenceNumber(seq),
		OnRampAddressLength:  20,
		OnRampAddress:        make([]byte, 20),
		OffRampAddressLength: 20,
		OffRampAddress:       make([]byte, 20),
		Finality:             10,
		ExecutionGasLimit:    100000,
		CcipReceiveGasLimit:  50000,
		CcvAndExecutorHash:   ccvAndExecutorHash,
		SenderLength:         20,
		Sender:               make([]byte, 20),
		ReceiverLength:       20,
		Receiver:             make([]byte, 20),
		DestBlobLength:       0,
		DestBlob:             nil,
		TokenTransferLength:  0,
		TokenTransfer:        nil,
		DataLength:           8,
		Data:                 []byte("testdata"),
	}
}

// signMessage signs a message with the given signer and returns a WriteRequest.
func (f *aggregatorTestFixture) signMessage(t *testing.T, signer *testSigner, msg *protocol.Message) *committeepb.WriteCommitteeVerifierNodeResultRequest {
	ccvVersion := []byte{0x01, 0x02, 0x03, 0x04}
	executorAddr := make([]byte, 20)
	ccvAddr, err := protocol.NewUnknownAddressFromHex(f.verifierAddress)
	require.NoError(t, err)

	messageID, err := msg.MessageID()
	require.NoError(t, err)

	hash, err := committee.NewSignableHash(messageID, ccvVersion)
	require.NoError(t, err)

	r32, s32, signerAddr, err := protocol.SignV27(hash[:], signer.privateKey)
	require.NoError(t, err)

	sigData := protocol.Data{R: r32, S: s32, Signer: signerAddr}
	signature, err := protocol.EncodeSingleECDSASignature(sigData)
	require.NoError(t, err)

	return &committeepb.WriteCommitteeVerifierNodeResultRequest{
		CommitteeVerifierNodeResult: &committeepb.CommitteeVerifierNodeResult{
			Message: &verifierpb.Message{
				Version:              uint32(msg.Version),
				SourceChainSelector:  uint64(msg.SourceChainSelector),
				DestChainSelector:    uint64(msg.DestChainSelector),
				SequenceNumber:       uint64(msg.SequenceNumber),
				OnRampAddressLength:  uint32(msg.OnRampAddressLength),
				OnRampAddress:        msg.OnRampAddress,
				OffRampAddressLength: uint32(msg.OffRampAddressLength),
				OffRampAddress:       msg.OffRampAddress,
				Finality:             uint32(msg.Finality),
				ExecutionGasLimit:    msg.ExecutionGasLimit,
				CcipReceiveGasLimit:  msg.CcipReceiveGasLimit,
				CcvAndExecutorHash:   msg.CcvAndExecutorHash[:],
				SenderLength:         uint32(msg.SenderLength),
				Sender:               msg.Sender,
				ReceiverLength:       uint32(msg.ReceiverLength),
				Receiver:             msg.Receiver,
				DestBlobLength:       uint32(msg.DestBlobLength),
				DestBlob:             msg.DestBlob,
				TokenTransferLength:  uint32(msg.TokenTransferLength),
				TokenTransfer:        nil,
				DataLength:           uint32(msg.DataLength),
				Data:                 msg.Data,
			},
			CcvVersion:      ccvVersion,
			CcvAddresses:    [][]byte{ccvAddr.Bytes()},
			ExecutorAddress: executorAddr,
			Signature:       signature,
		},
	}
}

// assertHonestQuorumReached verifies that 2 honest signers can still reach quorum.
func (f *aggregatorTestFixture) assertHonestQuorumReached(t *testing.T, ctx context.Context) {
	msg := f.createValidMessage(t)
	messageID, err := msg.MessageID()
	require.NoError(t, err)

	// Submit from honest signer 1 using their own client
	req1 := f.signMessage(t, f.honestSigner1, msg)
	resp1, err := f.honest1CommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req1)
	require.NoError(t, err, "honest signer 1 should succeed")
	require.Equal(t, committeepb.WriteStatus_SUCCESS, resp1.Status)

	// Submit from honest signer 2 using their own client
	req2 := f.signMessage(t, f.honestSigner2, msg)
	resp2, err := f.honest2CommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req2)
	require.NoError(t, err, "honest signer 2 should succeed")
	require.Equal(t, committeepb.WriteStatus_SUCCESS, resp2.Status)

	// Wait for aggregation
	time.Sleep(200 * time.Millisecond)

	// Verify quorum was reached by querying the result
	getResp, err := f.verifierClient.GetVerifierResultsForMessage(ctx, &verifierpb.GetVerifierResultsForMessageRequest{
		MessageIds: [][]byte{messageID[:]},
	})
	require.NoError(t, err)
	require.Len(t, getResp.Results, 1, "should have aggregated result")
	require.NotNil(t, getResp.Results[0], "result should not be nil")
}

// setupAggregatorTestFixture creates the test infrastructure with 2-of-3 quorum.
func setupAggregatorTestFixture(t *testing.T) *aggregatorTestFixture {
	committeeName := "test"
	sourceChainSel := uint64(12922642891491394802)
	destChainSel := uint64(2)
	verifierAddress := "0x68B1D87F95878fE05B998F19b66F4baba5De1aed"
	grpcHostPort := 50151 // Direct gRPC port for test

	// Create 3 signers: 2 honest, 1 malicious
	honest1 := newTestSigner(t, committeeName, 0)
	honest2 := newTestSigner(t, committeeName, 1)
	malicious := newTestSigner(t, committeeName, 2)

	// Separate credentials for each verifier
	honest1Credentials := hmacutil.MustGenerateCredentials()
	honest2Credentials := hmacutil.MustGenerateCredentials()
	maliciousCredentials := hmacutil.MustGenerateCredentials()

	// Setup aggregator with 2-of-3 threshold
	out, err := services.NewAggregator(&services.AggregatorInput{
		CommitteeName:   committeeName,
		Image:           "aggregator:dev",
		HostPort:        8110,
		ExposedHostPort: grpcHostPort, // Expose gRPC port directly for test
		SourceCodePath:  "../../../aggregator",
		RootPath:        "../../../../",
		CommitteeVerifierResolverAddresses: map[uint64]string{
			sourceChainSel: verifierAddress,
		},
		ThresholdPerSource: map[uint64]uint8{
			sourceChainSel: 2, // 2-of-3 threshold
		},
		AggregationChannelBufferSize: 1, // Minimal buffer for channel exhaustion tests
		BackgroundWorkerCount:        1, // Single worker = slow drain for deterministic tests
		DB: &services.AggregatorDBInput{
			Image:    "postgres:16-alpine",
			HostPort: 7440,
		},
		Redis: &services.AggregatorRedisInput{
			Image:    "redis:7-alpine",
			HostPort: 6390,
		},
		Env: &services.AggregatorEnvConfig{
			StorageConnectionURL: fmt.Sprintf("postgresql://%s:%s@test-aggregator-db:5432/%s?sslmode=disable",
				services.DefaultAggregatorDBUsername,
				services.DefaultAggregatorDBPassword,
				services.DefaultAggregatorDBName,
			),
			RedisAddress:  "test-aggregator-redis:6379",
			RedisPassword: "",
			RedisDB:       "0",
		},
		APIClients: []*services.AggregatorClientConfig{
			{
				ClientID:    "honest-verifier-1",
				Description: "Honest verifier 1 client",
				Enabled:     true,
				Groups:      []string{"verifiers"},
				APIKeyPairs: []*services.AggregatorAPIKeyPair{{
					APIKey: honest1Credentials.APIKey,
					Secret: honest1Credentials.Secret,
				}},
			},
			{
				ClientID:    "honest-verifier-2",
				Description: "Honest verifier 2 client",
				Enabled:     true,
				Groups:      []string{"verifiers"},
				APIKeyPairs: []*services.AggregatorAPIKeyPair{{
					APIKey: honest2Credentials.APIKey,
					Secret: honest2Credentials.Secret,
				}},
			},
			{
				ClientID:    "malicious-verifier",
				Description: "Malicious verifier client",
				Enabled:     true,
				Groups:      []string{"service-tests"}, // Low rate limit group for testing
				APIKeyPairs: []*services.AggregatorAPIKeyPair{{
					APIKey: maliciousCredentials.APIKey,
					Secret: maliciousCredentials.Secret,
				}},
			},
		},
	}, []*services.VerifierInput{
		// All 3 signers are in the committee
		{
			SourceCodePath:   "../../../verifier",
			RootPath:         "../../../../",
			CommitteeName:    committeeName,
			NodeIndex:        0,
			SigningKey:       honest1.privateKeyHex,
			SigningKeyPublic: honest1.publicKeyHex,
		},
		{
			SourceCodePath:   "../../../verifier",
			RootPath:         "../../../../",
			CommitteeName:    committeeName,
			NodeIndex:        1,
			SigningKey:       honest2.privateKeyHex,
			SigningKeyPublic: honest2.publicKeyHex,
		},
		{
			SourceCodePath:   "../../../verifier",
			RootPath:         "../../../../",
			CommitteeName:    committeeName,
			NodeIndex:        2,
			SigningKey:       malicious.privateKeyHex,
			SigningKeyPublic: malicious.publicKeyHex,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, out)

	// Create authenticated gRPC connections - separate for each signer
	grpcAddress := fmt.Sprintf("localhost:%d", grpcHostPort)

	createAuthenticatedConn := func(creds hmacutil.Credentials) *grpc.ClientConn {
		interceptor := hmacutil.NewClientInterceptor(&hmacutil.ClientConfig{
			APIKey: creds.APIKey,
			Secret: creds.Secret,
		})
		conn, connErr := grpc.NewClient(
			grpcAddress,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithUnaryInterceptor(interceptor),
		)
		require.NoError(t, connErr)
		return conn
	}

	honest1Conn := createAuthenticatedConn(honest1Credentials)
	honest2Conn := createAuthenticatedConn(honest2Credentials)
	maliciousConn := createAuthenticatedConn(maliciousCredentials)

	t.Cleanup(func() {
		honest1Conn.Close()
		honest2Conn.Close()
		maliciousConn.Close()
	})

	return &aggregatorTestFixture{
		aggregatorOutput:         out,
		honest1Credentials:       honest1Credentials,
		honest2Credentials:       honest2Credentials,
		maliciousCredentials:     maliciousCredentials,
		honestSigner1:            honest1,
		honestSigner2:            honest2,
		maliciousSigner:          malicious,
		sourceChainSel:           sourceChainSel,
		destChainSel:             destChainSel,
		verifierAddress:          verifierAddress,
		honest1CommitteeClient:   committeepb.NewCommitteeVerifierClient(honest1Conn),
		honest2CommitteeClient:   committeepb.NewCommitteeVerifierClient(honest2Conn),
		maliciousCommitteeClient: committeepb.NewCommitteeVerifierClient(maliciousConn),
		verifierClient:           verifierpb.NewVerifierClient(honest1Conn),
		honest1Conn:              honest1Conn,
		honest2Conn:              honest2Conn,
		maliciousConn:            maliciousConn,
		sequenceCounter:          1000, // Start high to avoid collisions
	}
}

func TestServiceAggregatorSecurityFeatures(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	fixture := setupAggregatorTestFixture(t)
	ctx := context.Background()

	t.Run("bad data should be rejected", func(t *testing.T) {
		t.Run("empty signature should be rejected", func(t *testing.T) {
			msg := fixture.createValidMessage(t)
			req := fixture.signMessage(t, fixture.maliciousSigner, msg)
			req.CommitteeVerifierNodeResult.Signature = []byte{} // Empty signature

			_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.Error(t, err, "empty signature should be rejected")
			st, _ := status.FromError(err)
			require.Equal(t, codes.InvalidArgument, st.Code())
		})

		t.Run("duplicate submission should be handled", func(t *testing.T) {
			msg := fixture.createValidMessage(t)
			req := fixture.signMessage(t, fixture.maliciousSigner, msg)

			_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.NoError(t, err, "first submission should succeed")

			_, err = fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.NoError(t, err, "duplicate submission should be handled")
		})

		t.Run("empty ccv_addresses array should be rejected", func(t *testing.T) {
			msg := fixture.createValidMessage(t)
			req := fixture.signMessage(t, fixture.maliciousSigner, msg)
			req.CommitteeVerifierNodeResult.CcvAddresses = [][]byte{} // Empty array

			_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.Error(t, err, "empty CCV addresses should be rejected")
		})

		t.Run("nil ccv_addresses should be rejected", func(t *testing.T) {
			msg := fixture.createValidMessage(t)
			req := fixture.signMessage(t, fixture.maliciousSigner, msg)
			req.CommitteeVerifierNodeResult.CcvAddresses = nil

			_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.Error(t, err, "nil CCV addresses should be rejected")
		})

		t.Run("source equals destination chain selector should be rejected", func(t *testing.T) {
			msg := fixture.createValidMessage(t)
			msg.DestChainSelector = msg.SourceChainSelector // Same chain
			req := fixture.signMessage(t, fixture.maliciousSigner, msg)

			_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.Error(t, err, "source equals destination chain selector should be rejected")
		})

		t.Run("corrupted signature bytes should be rejected", func(t *testing.T) {
			msg := fixture.createValidMessage(t)
			req := fixture.signMessage(t, fixture.maliciousSigner, msg)
			// Corrupt the signature with random bytes
			req.CommitteeVerifierNodeResult.Signature = []byte{0xde, 0xad, 0xbe, 0xef}

			_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.Error(t, err, "corrupted signature should be rejected")
		})

		t.Run("zero sequence number should be handled", func(t *testing.T) {
			msg := fixture.createValidMessage(t)
			msg.SequenceNumber = 0
			req := fixture.signMessage(t, fixture.maliciousSigner, msg)

			_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.NoError(t, err, "zero sequence number should be handled")
		})

		t.Run("wrong ccvAndExecutorHash length should be rejected", func(t *testing.T) {
			msg := fixture.createValidMessage(t)
			req := fixture.signMessage(t, fixture.maliciousSigner, msg)
			req.CommitteeVerifierNodeResult.Message.CcvAndExecutorHash = make([]byte, 16) // Wrong length

			_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.Error(t, err, "wrong hash length should be rejected")
			st, _ := status.FromError(err)
			require.Equal(t, codes.InvalidArgument, st.Code())
		})

		t.Run("empty executor address should be handled", func(t *testing.T) {
			msg := fixture.createValidMessage(t)
			req := fixture.signMessage(t, fixture.maliciousSigner, msg)
			req.CommitteeVerifierNodeResult.ExecutorAddress = []byte{}

			_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.Error(t, err, "empty executor address should be handled")
		})

		t.Run("empty batch request should be rejected", func(t *testing.T) {
			batchReq := &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{
				Requests: []*committeepb.WriteCommitteeVerifierNodeResultRequest{},
			}

			_, err := fixture.honest1CommitteeClient.BatchWriteCommitteeVerifierNodeResult(ctx, batchReq)
			require.Error(t, err, "empty batch should be rejected")
			st, _ := status.FromError(err)
			require.Equal(t, codes.InvalidArgument, st.Code())
		})

		t.Run("nil batch requests should be rejected", func(t *testing.T) {
			batchReq := &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{
				Requests: nil,
			}

			_, err := fixture.honest1CommitteeClient.BatchWriteCommitteeVerifierNodeResult(ctx, batchReq)
			require.Error(t, err, "nil batch should be rejected")
		})

		t.Run("signature from unknown signer should be rejected", func(t *testing.T) {
			// Create a signer not in the committee
			unknownSigner := newTestSigner(t, "unknown", 99)
			msg := fixture.createValidMessage(t)
			req := fixture.signMessage(t, unknownSigner, msg)

			_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.Error(t, err, "unknown signer should be rejected")
		})

		t.Run("mismatched ccvAndExecutorHash should be rejected", func(t *testing.T) {
			msg := fixture.createValidMessage(t)
			req := fixture.signMessage(t, fixture.maliciousSigner, msg)
			// Corrupt the hash in the message
			req.CommitteeVerifierNodeResult.Message.CcvAndExecutorHash = make([]byte, 32)

			_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.Error(t, err, "mismatched hash should be rejected")
			st, _ := status.FromError(err)
			require.Equal(t, codes.InvalidArgument, st.Code())
		})

		t.Run("nil message should be rejected", func(t *testing.T) {
			req := &committeepb.WriteCommitteeVerifierNodeResultRequest{
				CommitteeVerifierNodeResult: &committeepb.CommitteeVerifierNodeResult{
					Message:    nil,
					CcvVersion: []byte{0x01, 0x02, 0x03, 0x04},
					Signature:  []byte{0x01, 0x02},
				},
			}

			_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.Error(t, err, "nil message should be rejected")
			st, _ := status.FromError(err)
			require.Equal(t, codes.InvalidArgument, st.Code())
		})

		t.Run("invalid ccvVersion length should be rejected", func(t *testing.T) {
			msg := fixture.createValidMessage(t)
			req := fixture.signMessage(t, fixture.maliciousSigner, msg)
			req.CommitteeVerifierNodeResult.CcvVersion = []byte{0x01} // Too short

			_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.Error(t, err, "short ccvVersion should be rejected")
		})

		t.Run("invalid source chain selector should be rejected", func(t *testing.T) {
			msg := fixture.createValidMessage(t)
			msg.SourceChainSelector = 99999 // Not in quorum config
			req := fixture.signMessage(t, fixture.maliciousSigner, msg)

			_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.Error(t, err, "invalid source chain should be rejected")
		})

		t.Run("extremely large data field should be handled", func(t *testing.T) {
			msg := fixture.createValidMessage(t)
			// Try to set a very large data field
			largeData := make([]byte, 65535) // Max uint16
			msg.Data = largeData
			msg.DataLength = uint16(len(largeData))
			req := fixture.signMessage(t, fixture.maliciousSigner, msg)

			_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.Error(t, err, "extremely large data field should be handled")
		})

		// Health assertion: honest verifiers can still reach quorum
		t.Run("honest verifiers can still reach quorum after crash attacks", func(t *testing.T) {
			fixture.assertHonestQuorumReached(t, ctx)
		})
	})

	t.Run("rate limiting should be enforced", func(t *testing.T) {
		t.Run("rapid valid submissions exceeding rate limit should be rejected", func(t *testing.T) {
			var wg sync.WaitGroup
			rateLimitedCount := 0
			successCount := 0
			var mu sync.Mutex

			// Malicious client uses service-tests group with 50/min limit
			numRequests := 100
			for i := 0; i < numRequests; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					msg := fixture.createValidMessage(t)
					req := fixture.signMessage(t, fixture.maliciousSigner, msg)
					_, err := fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
					mu.Lock()
					if err != nil && status.Code(err) == codes.ResourceExhausted {
						rateLimitedCount++
					} else if err == nil {
						successCount++
					}
					mu.Unlock()
				}()
			}
			wg.Wait()

			t.Logf("Rate limiting test: %d/%d requests rate limited, %d succeeded", rateLimitedCount, numRequests, successCount)
			require.Greater(t, rateLimitedCount, 0, "some requests should be rate limited when exceeding 50/min limit")
		})

		t.Run("batch endpoint with max size should be handled", func(t *testing.T) {
			// Create a batch of 100 requests (max allowed)
			// Uses honest client to avoid rate limit issues
			requests := make([]*committeepb.WriteCommitteeVerifierNodeResultRequest, 100)
			for i := 0; i < 100; i++ {
				msg := fixture.createValidMessage(t)
				requests[i] = fixture.signMessage(t, fixture.honestSigner1, msg)
			}

			batchReq := &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{
				Requests: requests,
			}

			resp, err := fixture.honest1CommitteeClient.BatchWriteCommitteeVerifierNodeResult(ctx, batchReq)
			require.NoError(t, err, "batch request should be handled")
			require.NotNil(t, resp, "response should not be nil")
		})

		t.Run("batch endpoint exceeding max size should be rejected", func(t *testing.T) {
			// Create a batch exceeding the 100 limit
			// Uses honest client to avoid rate limit issues
			requests := make([]*committeepb.WriteCommitteeVerifierNodeResultRequest, 101)
			for i := 0; i < 101; i++ {
				msg := fixture.createValidMessage(t)
				requests[i] = fixture.signMessage(t, fixture.honestSigner1, msg)
			}

			batchReq := &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{
				Requests: requests,
			}

			_, err := fixture.honest1CommitteeClient.BatchWriteCommitteeVerifierNodeResult(ctx, batchReq)
			require.Error(t, err, "exceeding batch limit should be rejected")
			st, _ := status.FromError(err)
			require.Equal(t, codes.InvalidArgument, st.Code())
		})

		t.Run("rate_limit_should_be_per_client_isolated", func(t *testing.T) {
			// Exhaust malicious client's rate limit
			numRequests := 100
			for i := 0; i < numRequests; i++ {
				go func() {
					msg := fixture.createValidMessage(t)
					req := fixture.signMessage(t, fixture.maliciousSigner, msg)
					_, _ = fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
				}()
			}
			time.Sleep(100 * time.Millisecond)

			// Honest client should still be able to submit
			msg := fixture.createValidMessage(t)
			req := fixture.signMessage(t, fixture.honestSigner1, msg)
			_, err := fixture.honest1CommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)
			require.NoError(t, err, "honest client should not be affected by malicious client's rate limit")
		})

		// Health assertion: honest verifiers can still reach quorum after DoS attempts
		t.Run("honest verifiers can still reach quorum after DoS attacks", func(t *testing.T) {
			fixture.assertHonestQuorumReached(t, ctx)
		})
	})

	// Channel exhaustion vulnerability tests
	// Channel exhaustion regression tests - verify fix is in place
	t.Run("channel_exhaustion_protection", func(t *testing.T) {
		t.Run("concurrent_submissions_should_not_block_honest_verifiers", func(t *testing.T) {
			// Wait for any pending aggregations to drain
			time.Sleep(500 * time.Millisecond)

			// With the fix in place (per-client channel isolation), concurrent submissions
			// from a malicious client should not affect honest clients.
			numMalicious := 10
			maliciousErrs := make([]error, numMalicious)
			var wg sync.WaitGroup

			// Pre-create all messages and requests
			maliciousReqs := make([]*committeepb.WriteCommitteeVerifierNodeResultRequest, numMalicious)
			for i := 0; i < numMalicious; i++ {
				msg := fixture.createValidMessage(t)
				maliciousReqs[i] = fixture.signMessage(t, fixture.maliciousSigner, msg)
			}

			// Launch all malicious submissions concurrently
			for i := 0; i < numMalicious; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					_, maliciousErrs[idx] = fixture.maliciousCommitteeClient.WriteCommitteeVerifierNodeResult(ctx, maliciousReqs[idx])
				}(i)
			}
			wg.Wait()

			// Honest verifier should always be able to submit (isolated channel)
			msg := fixture.createValidMessage(t)
			req := fixture.signMessage(t, fixture.honestSigner1, msg)
			_, honestErr := fixture.honest1CommitteeClient.WriteCommitteeVerifierNodeResult(ctx, req)

			require.NoError(t, honestErr, "Honest verifier should not be blocked by malicious traffic")
		})

		t.Run("large_batch_request_should_succeed_with_isolated_channels", func(t *testing.T) {
			// Wait for any pending aggregations to drain
			time.Sleep(500 * time.Millisecond)

			// With the fix, each client has their own channel, so batch requests
			// should succeed regardless of channel buffer size
			var requests []*committeepb.WriteCommitteeVerifierNodeResultRequest
			for i := 0; i < 10; i++ {
				msg := fixture.createValidMessage(t)
				req := fixture.signMessage(t, fixture.honestSigner1, msg)
				requests = append(requests, req)
			}

			// Submit as a single batch
			batchReq := &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{
				Requests: requests,
			}
			resp, err := fixture.honest1CommitteeClient.BatchWriteCommitteeVerifierNodeResult(ctx, batchReq)

			require.NoError(t, err, "Batch request should not fail")
			require.NotNil(t, resp, "Response should not be nil")

			failedCount := 0
			for _, result := range resp.GetResponses() {
				if result.Status == committeepb.WriteStatus_FAILED {
					failedCount++
				}
			}

			require.Equal(t, 0, failedCount, "No batch items should fail due to channel exhaustion")
		})
	})
}
