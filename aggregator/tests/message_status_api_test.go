package tests

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/testutil"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
	msgdiscoverypb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-discovery/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

var (
	ccvVersionA = []byte{0x01, 0x02, 0x03, 0x04}
	ccvVersionB = []byte{0x01, 0x02, 0x03, 0x05}
)

// statusTestEnv holds an authenticated write client and an anonymous status client for one message.
type statusTestEnv struct {
	t                     *testing.T
	committee             *model.Committee
	sourceVerifierAddress []byte
	writeClient           committeepb.CommitteeVerifierClient
	statusClient          committeepb.CommitteeVerifierClient
	message               *protocol.Message
	messageID             []byte
}

func newStatusTestEnv(t *testing.T, threshold uint8, signers ...*testutil.SignerFixture) *statusTestEnv {
	t.Helper()
	sourceVerifierAddress, destVerifierAddress := testutil.GenerateVerifierAddresses(t)
	committee := testutil.NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signerConfigs(signers)...)
	testutil.UpdateCommitteeQuorumWithThreshold(committee, sourceVerifierAddress, threshold, signerConfigs(signers)...)

	listener, cleanup, err := CreateServerOnly(t, WithCommitteeConfig(committee))
	require.NoError(t, err)
	t.Cleanup(cleanup)
	writeClient, _, _, clientCleanup := CreateAuthenticatedClient(t, listener)
	t.Cleanup(clientCleanup)

	message := testutil.NewProtocolMessage(t)
	_, messageID := testutil.NewMessageWithCCVNodeData(t, message, sourceVerifierAddress)
	return &statusTestEnv{
		t:                     t,
		committee:             committee,
		sourceVerifierAddress: sourceVerifierAddress,
		writeClient:           writeClient,
		statusClient:          createAnonymousStatusClient(t, listener),
		message:               message,
		messageID:             messageID[:],
	}
}

func signerConfigs(signers []*testutil.SignerFixture) []model.Signer {
	configs := make([]model.Signer, 0, len(signers))
	for _, signer := range signers {
		configs = append(configs, signer.Signer)
	}
	return configs
}

func (e *statusTestEnv) write(signer *testutil.SignerFixture, ccvVersion []byte) {
	e.t.Helper()
	nodeData, _ := testutil.NewMessageWithCCVNodeData(e.t, e.message, e.sourceVerifierAddress,
		testutil.WithCcvVersion(ccvVersion), testutil.WithSignatureFrom(e.t, signer))
	resp, err := e.writeClient.WriteCommitteeVerifierNodeResult(e.t.Context(), testutil.NewWriteCommitteeVerifierNodeResultRequest(nodeData))
	require.NoError(e.t, err)
	require.Equal(e.t, committeepb.WriteStatus_SUCCESS, resp.Status)
}

func (e *statusTestEnv) updateCommittee(threshold uint8, signers ...*testutil.SignerFixture) {
	testutil.UpdateCommitteeQuorumWithThreshold(e.committee, e.sourceVerifierAddress, threshold, signerConfigs(signers)...)
}

func (e *statusTestEnv) requireStatus(count, threshold uint32, aggregated bool) {
	e.t.Helper()
	requireMessageStatus(e.t, e.statusClient, e.messageID, count, threshold, aggregated)
}

// createServerAndClientsWithStatus is CreateServerAndClient plus an anonymous status client.
func createServerAndClientsWithStatus(t *testing.T, options ...ConfigOption) (committeepb.CommitteeVerifierClient, verifierpb.VerifierClient, msgdiscoverypb.MessageDiscoveryClient, committeepb.CommitteeVerifierClient) {
	t.Helper()
	listener, cleanup, err := CreateServerOnly(t, options...)
	require.NoError(t, err)
	t.Cleanup(cleanup)
	writeClient, verifierClient, discoveryClient, clientCleanup := CreateAuthenticatedClient(t, listener, options...)
	t.Cleanup(clientCleanup)
	return writeClient, verifierClient, discoveryClient, createAnonymousStatusClient(t, listener)
}

// requireMessageStatus waits until GetMessageStatus returns the expected progress.
func requireMessageStatus(t *testing.T, client committeepb.CommitteeVerifierClient, messageID []byte, count, threshold uint32, aggregated bool) {
	t.Helper()
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		resp, err := client.GetMessageStatus(t.Context(), &committeepb.GetMessageStatusRequest{MessageId: messageID})
		require.NoError(collect, err)
		require.Equal(collect, count, resp.GetVerificationCount(), "verification count")
		require.Equal(collect, threshold, resp.GetThreshold(), "threshold")
		require.Equal(collect, aggregated, resp.GetAggregated(), "aggregated")
	}, 5*time.Second, 100*time.Millisecond)
}

// createAnonymousStatusClient dials the status service without HMAC credentials.
func createAnonymousStatusClient(t *testing.T, listener *bufconn.Listener) committeepb.CommitteeVerifierClient {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return committeepb.NewCommitteeVerifierClient(conn)
}

func TestGetMessageStatus_QuorumProgress(t *testing.T) {
	t.Parallel()
	signer1 := testutil.NewSignerFixture(t, "node1")
	signer2 := testutil.NewSignerFixture(t, "node2")
	signer3 := testutil.NewSignerFixture(t, "node3")
	env := newStatusTestEnv(t, 2, signer1, signer2, signer3)

	_, err := env.statusClient.GetMessageStatus(t.Context(), &committeepb.GetMessageStatusRequest{MessageId: []byte{0x01}})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = env.statusClient.GetMessageStatus(t.Context(), &committeepb.GetMessageStatusRequest{MessageId: make([]byte, 32)})
	require.Equal(t, codes.NotFound, status.Code(err))

	// Only GetMessageStatus is public; the other CommitteeVerifier methods still require HMAC.
	_, err = env.statusClient.ReadCommitteeVerifierNodeResult(t.Context(), &committeepb.ReadCommitteeVerifierNodeResultRequest{})
	require.Equal(t, codes.Unauthenticated, status.Code(err))

	env.write(signer1, ccvVersionA)
	env.requireStatus(1, 2, false)

	env.write(signer2, ccvVersionA)
	env.requireStatus(2, 2, true)

	// A verification after the quorum is still counted.
	env.write(signer3, ccvVersionA)
	env.requireStatus(3, 2, true)

	resp, err := env.statusClient.GetMessageStatus(t.Context(), &committeepb.GetMessageStatusRequest{MessageId: env.messageID})
	require.NoError(t, err)
	require.Positive(t, resp.GetFirstVerificationAt())
	require.GreaterOrEqual(t, resp.GetLatestVerificationAt(), resp.GetFirstVerificationAt())
	require.GreaterOrEqual(t, resp.GetAggregatedAt(), resp.GetFirstVerificationAt(), "the report comes after the first verification")
}

func TestGetMessageStatus_CommitteeChangeBeforeAggregation(t *testing.T) {
	t.Parallel()
	signer1 := testutil.NewSignerFixture(t, "node1")
	signer2 := testutil.NewSignerFixture(t, "node2")
	signer3 := testutil.NewSignerFixture(t, "node3")
	signer4 := testutil.NewSignerFixture(t, "node4")
	env := newStatusTestEnv(t, 3, signer1, signer2, signer3)

	env.write(signer1, ccvVersionA)
	env.write(signer2, ccvVersionA)
	env.requireStatus(2, 3, false)

	// Remove signer1, add signer4 and lower the threshold. The API uses the current config on each call.
	env.updateCommittee(2, signer2, signer3, signer4)
	env.requireStatus(1, 2, false)

	env.write(signer4, ccvVersionA)
	env.requireStatus(2, 2, true)
}

func TestGetMessageStatus_CommitteeChangeAfterAggregation(t *testing.T) {
	t.Parallel()
	signer1 := testutil.NewSignerFixture(t, "node1")
	signer2 := testutil.NewSignerFixture(t, "node2")
	signer3 := testutil.NewSignerFixture(t, "node3")
	signer4 := testutil.NewSignerFixture(t, "node4")
	env := newStatusTestEnv(t, 2, signer1, signer2, signer3)

	env.write(signer1, ccvVersionA)
	env.write(signer2, ccvVersionA)
	env.requireStatus(2, 2, true)

	// Remove signer1, add signer4 and raise the threshold.
	// The result API rejects the stored report under the new committee, so aggregated becomes false.
	env.updateCommittee(3, signer2, signer3, signer4)
	env.requireStatus(1, 3, false)

	// The new writes produce a new report that is valid under the new committee.
	env.write(signer3, ccvVersionA)
	env.write(signer4, ccvVersionA)
	env.requireStatus(3, 3, true)
}

func TestGetMessageStatus_MultipleAggregationKeys(t *testing.T) {
	t.Parallel()
	signer1 := testutil.NewSignerFixture(t, "node1")
	signer2 := testutil.NewSignerFixture(t, "node2")
	signer3 := testutil.NewSignerFixture(t, "node3")
	env := newStatusTestEnv(t, 2, signer1, signer2, signer3)

	// Each CCV version gives a different aggregation key.
	env.write(signer1, ccvVersionA)
	env.write(signer2, ccvVersionB)
	env.requireStatus(1, 2, false)

	// Key B reaches the quorum, so the API reports the key of the aggregated report.
	env.write(signer3, ccvVersionB)
	env.requireStatus(2, 2, true)

	// Key A also reaches the quorum. The latest report is for key A, and both keys have 2 signers.
	env.write(signer2, ccvVersionA)
	env.requireStatus(2, 2, true)
}
