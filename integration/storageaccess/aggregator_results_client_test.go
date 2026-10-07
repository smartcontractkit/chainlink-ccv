package storageaccess

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

// fakeVerifierServer answers per-ID lookups: results carry ccv_data, perErr forces a
// per-ID error entry, everything else defaults to NotFound — mirroring the
// aggregator's 1:1 results/errors correspondence.
type fakeVerifierServer struct {
	verifierpb.UnimplementedVerifierServer
	results map[string][]byte // string(messageID) → ccv_data
	perErr  map[string]*rpcstatus.Status
	callErr error
	empty   bool // return a response with no entries at all
}

func (f *fakeVerifierServer) GetVerifierResultsForMessage(_ context.Context, req *verifierpb.GetVerifierResultsForMessageRequest) (*verifierpb.GetVerifierResultsForMessageResponse, error) {
	if f.callErr != nil {
		return nil, f.callErr
	}
	if f.empty {
		return &verifierpb.GetVerifierResultsForMessageResponse{}, nil
	}
	resp := &verifierpb.GetVerifierResultsForMessageResponse{}
	for _, id := range req.GetMessageIds() {
		if st, ok := f.perErr[string(id)]; ok {
			resp.Results = append(resp.Results, nil)
			resp.Errors = append(resp.Errors, st)
			continue
		}
		if ccvData, ok := f.results[string(id)]; ok {
			resp.Results = append(resp.Results, &verifierpb.VerifierResult{CcvData: ccvData})
			resp.Errors = append(resp.Errors, &rpcstatus.Status{Code: int32(codes.OK)})
			continue
		}
		resp.Results = append(resp.Results, nil)
		resp.Errors = append(resp.Errors, &rpcstatus.Status{Code: int32(codes.NotFound), Message: "message ID not found"})
	}
	return resp, nil
}

// bufconnResultsClient serves srv over bufconn and returns a ResultsClient wired to it.
func bufconnResultsClient(t *testing.T, srv verifierpb.VerifierServer) ResultsClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	grpcSrv := grpc.NewServer()
	verifierpb.RegisterVerifierServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return &aggregatorResultsClient{client: verifierpb.NewVerifierClient(conn), conn: conn}
}

func TestResultsClientEntryTranslation(t *testing.T) {
	attested := []byte{0xde, 0xad}
	srv := &fakeVerifierServer{
		results: map[string][]byte{"id-attested": attested, "id-empty": {}},
		perErr:  map[string]*rpcstatus.Status{"id-err": {Code: int32(codes.NotFound), Message: "message ID not found"}},
	}
	client := bufconnResultsClient(t, srv)

	entries, err := client.GetVerifierResultsForMessage(context.Background(),
		[][]byte{[]byte("id-attested"), []byte("id-err"), []byte("id-empty")})
	require.NoError(t, err)
	require.Len(t, entries, 3)

	require.True(t, entries[0].Present)
	require.Equal(t, int32(codes.OK), entries[0].ErrorCode)
	require.Equal(t, attested, entries[0].CcvData)

	require.True(t, entries[1].Present)
	require.Equal(t, int32(codes.NotFound), entries[1].ErrorCode)
	require.Equal(t, "message ID not found", entries[1].ErrorMsg)
	require.Empty(t, entries[1].CcvData)

	require.True(t, entries[2].Present)
	require.Empty(t, entries[2].CcvData, "empty ccv data stays an empty result entry")
}

func TestResultsClientMissingEntry(t *testing.T) {
	client := bufconnResultsClient(t, &fakeVerifierServer{empty: true})

	entries, err := client.GetVerifierResultsForMessage(context.Background(), [][]byte{[]byte("id-any")})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.False(t, entries[0].Present, "a short batch response leaves the entry unpresent")
}

func TestResultsClientCallError(t *testing.T) {
	client := bufconnResultsClient(t, &fakeVerifierServer{callErr: errors.New("internal")})

	_, err := client.GetVerifierResultsForMessage(context.Background(), [][]byte{[]byte("id-any")})
	require.Error(t, err)
}
