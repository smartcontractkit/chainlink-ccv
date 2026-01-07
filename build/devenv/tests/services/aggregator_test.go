package services_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
	msgdiscoverypb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-discovery/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"

	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
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
func TestAggregatorAuthentication(t *testing.T) {
	committeeName := "auth-test"
	privateKey, publicKey, err := generateTestSigningKey(committeeName, 0)
	require.NoError(t, err)

	out, err := services.NewAggregator(&services.AggregatorInput{
		CommitteeName:  committeeName,
		Image:          "aggregator:dev",
		HostPort:       8104,
		SourceCodePath: "../../../aggregator",
		RootPath:       "../../../../",
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
	conn, err := grpc.NewClient(out.ExternalHTTPSUrl, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
