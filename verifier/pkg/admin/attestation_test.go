package admin

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
// per-ID error entry, everything else defaults to NotFound — mirroring the aggregator's
// 1:1 results/errors correspondence.
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

// installFakeVerifier serves srv over bufconn and points the aggregator dial seam at it.
func installFakeVerifier(t *testing.T, srv verifierpb.VerifierServer) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	grpcSrv := grpc.NewServer()
	verifierpb.RegisterVerifierServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	orig := dialVerifierClient
	dialVerifierClient = func(string) (verifierpb.VerifierClient, io.Closer, error) {
		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, nil, err
		}
		return verifierpb.NewVerifierClient(conn), conn, nil
	}
	t.Cleanup(func() { dialVerifierClient = orig })
}

func TestAggregatorAttested(t *testing.T) {
	id := rescheduleMsgID(1)
	installFakeVerifier(t, &fakeVerifierServer{results: map[string][]byte{string(id): {0xde, 0xad}}})

	results := checkNodeAttestations(context.Background(), NodeConfig{Name: "n1", AggregatorAddress: "bufnet"}, [][]byte{id})
	require.Len(t, results, 1)
	require.Equal(t, AttestationAttested, results[0].State)
	require.Contains(t, results[0].Detail, "aggregator")
}

func TestAggregatorPerIDErrorMeansNotFound(t *testing.T) {
	id := rescheduleMsgID(2)
	installFakeVerifier(t, &fakeVerifierServer{
		perErr: map[string]*rpcstatus.Status{string(id): {Code: int32(codes.NotFound), Message: "message ID not found"}},
	})

	results := checkNodeAttestations(context.Background(), NodeConfig{AggregatorAddress: "bufnet"}, [][]byte{id})
	require.Equal(t, AttestationNotFound, results[0].State)
	require.Contains(t, results[0].Detail, "message ID not found")
}

func TestAggregatorEmptyCcvDataMeansNotFound(t *testing.T) {
	id := rescheduleMsgID(3)
	installFakeVerifier(t, &fakeVerifierServer{results: map[string][]byte{string(id): {}}})

	results := checkNodeAttestations(context.Background(), NodeConfig{AggregatorAddress: "bufnet"}, [][]byte{id})
	require.Equal(t, AttestationNotFound, results[0].State)
}

func TestAggregatorCallErrorIsUnknown(t *testing.T) {
	installFakeVerifier(t, &fakeVerifierServer{callErr: errors.New("internal")})

	results := checkNodeAttestations(context.Background(), NodeConfig{AggregatorAddress: "bufnet"}, [][]byte{rescheduleMsgID(4)})
	require.Equal(t, AttestationUnknown, results[0].State)
	require.Contains(t, results[0].Detail, "aggregator unreachable")
}

func TestAggregatorMissingEntryIsUnknown(t *testing.T) {
	installFakeVerifier(t, &fakeVerifierServer{empty: true})

	results := checkNodeAttestations(context.Background(), NodeConfig{AggregatorAddress: "bufnet"}, [][]byte{rescheduleMsgID(5)})
	require.Equal(t, AttestationUnknown, results[0].State)
	require.Contains(t, results[0].Detail, "missing an entry")
}

func TestIndexerAttestationStates(t *testing.T) {
	id := rescheduleMsgID(6)
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		switch r.URL.Path {
		case "/v1/verifierresults/" + formatMessageID(id):
			w.Write([]byte(`{"success":true,"results":[{"verifierResult":{"ccv_data":"0x0102"},"metadata":{}}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	results := checkNodeAttestations(context.Background(), NodeConfig{IndexerURL: srv.URL}, [][]byte{id})
	require.Equal(t, AttestationAttested, results[0].State)
	require.Equal(t, "/v1/verifierresults/"+formatMessageID(id), gotPath)

	results = checkNodeAttestations(context.Background(), NodeConfig{IndexerURL: srv.URL}, [][]byte{rescheduleMsgID(7)})
	require.Equal(t, AttestationNotFound, results[0].State, "404 means not found")
}

func TestIndexerErrorStatusIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	results := checkNodeAttestations(context.Background(), NodeConfig{IndexerURL: srv.URL}, [][]byte{rescheduleMsgID(8)})
	require.Equal(t, AttestationUnknown, results[0].State)
	require.Contains(t, results[0].Detail, "500")
}

func TestAttestationNotConfiguredIsUnknown(t *testing.T) {
	results := checkNodeAttestations(context.Background(), NodeConfig{Name: "n1"}, [][]byte{rescheduleMsgID(9)})
	require.Len(t, results, 1)
	require.Equal(t, AttestationUnknown, results[0].State)
	require.Contains(t, results[0].Detail, "not configured")
}
