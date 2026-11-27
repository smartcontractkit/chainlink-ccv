package services_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	msgdiscoverypb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-discovery/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"

	v1 "github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/v1"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// fakeVerifiers stands in for the committee aggregator (gRPC) and a token verifier (REST) of the indexer.
// It uses only their wire contracts. Each message has a committee result and a token result that is held
// until the test releases it.
type fakeVerifiers struct {
	committeeAddr, tokenAddr, executorAddr protocol.UnknownAddress

	mu       sync.Mutex
	messages []*fakeMessage // in publish order; the discovery sequence of messages[i] is i+1
	byID     map[protocol.Bytes32]*fakeMessage

	// GRPCAddr and RESTBaseURL are the addresses that the indexer containers dial.
	GRPCAddr, RESTBaseURL string
}

type fakeMessage struct {
	committee, token *verifierpb.VerifierResult
	released         bool
}

// newFakeVerifiers starts both servers on free host ports. Containers reach them through host.docker.internal.
func newFakeVerifiers(t *testing.T) *fakeVerifiers {
	t.Helper()
	committee, err := protocol.NewUnknownAddressFromHex("0x1000000000000000000000000000000000000001")
	require.NoError(t, err)
	token, err := protocol.NewUnknownAddressFromHex("0x2000000000000000000000000000000000000002")
	require.NoError(t, err)
	executor, err := protocol.NewUnknownAddressFromHex("0x3000000000000000000000000000000000000003")
	require.NoError(t, err)
	f := &fakeVerifiers{committeeAddr: committee, tokenAddr: token, executorAddr: executor, byID: map[protocol.Bytes32]*fakeMessage{}}

	grpcLis, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	msgdiscoverypb.RegisterMessageDiscoveryServer(srv, &fakeDiscovery{f: f})
	verifierpb.RegisterVerifierServer(srv, &fakeCommittee{f: f})
	go func() { _ = srv.Serve(grpcLis) }()
	t.Cleanup(srv.Stop)

	restLis, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/verifications", f.serveTokenResults)
	httpSrv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(restLis) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	f.GRPCAddr = fmt.Sprintf("host.docker.internal:%d", grpcLis.Addr().(*net.TCPAddr).Port)
	f.RESTBaseURL = fmt.Sprintf("http://host.docker.internal:%d/v1", restLis.Addr().(*net.TCPAddr).Port)
	return f
}

// publish makes a new message discoverable with its committee result. Its token result is held.
func (f *fakeVerifiers) publish(t *testing.T, seq uint64) protocol.Bytes32 {
	t.Helper()
	ccvs := []protocol.UnknownAddress{f.committeeAddr, f.tokenAddr}
	hash, err := protocol.ComputeCCVAndExecutorHash(ccvs, f.executorAddr)
	require.NoError(t, err)
	zero := make([]byte, 20)
	msg := protocol.Message{
		Version: 1, SourceChainSelector: 12922642891491394802, DestChainSelector: 2, SequenceNumber: protocol.SequenceNumber(seq),
		OnRampAddressLength: 20, OnRampAddress: zero, OffRampAddressLength: 20, OffRampAddress: zero,
		Finality: 10, ExecutionGasLimit: 100000, CcipReceiveGasLimit: 50000, CcvAndExecutorHash: hash,
		SenderLength: 20, Sender: zero, ReceiverLength: 20, Receiver: zero, DataLength: 8, Data: []byte("testdata"),
	}
	id, err := msg.MessageID()
	require.NoError(t, err)
	result := func(source protocol.UnknownAddress) *verifierpb.VerifierResult {
		r, err := v1.NewVerifierResult(protocol.VerifierResult{
			MessageID: id, Message: msg, MessageCCVAddresses: ccvs, MessageExecutorAddress: f.executorAddr,
			CCVData: []byte{0x01}, Timestamp: time.Now(), VerifierSourceAddress: source, VerifierDestAddress: source,
		})
		require.NoError(t, err)
		return r.VerifierResult
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	m := &fakeMessage{committee: result(f.committeeAddr), token: result(f.tokenAddr)}
	f.messages = append(f.messages, m)
	f.byID[id] = m
	return id
}

// release makes the token verifier return the result of the message.
func (f *fakeVerifiers) release(id protocol.Bytes32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byID[id].released = true
}

// serveTokenResults answers like the token verifier: 404 if no requested message has a released result.
func (f *fakeVerifiers) serveTokenResults(w http.ResponseWriter, r *http.Request) {
	var results []v1.VerifierResult
	f.mu.Lock()
	for _, s := range r.URL.Query()["messageID"] {
		id, err := protocol.NewBytes32FromString(s)
		if m, ok := f.byID[id]; err == nil && ok && m.released {
			results = append(results, v1.VerifierResult{VerifierResult: m.token})
		}
	}
	f.mu.Unlock()
	if len(results) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v1.NewVerifierResultsResponse(results, nil))
}

type fakeDiscovery struct {
	msgdiscoverypb.UnimplementedMessageDiscoveryServer
	f *fakeVerifiers
}

// GetMessagesSince returns the committee results with a sequence at or above the request.
func (d *fakeDiscovery) GetMessagesSince(_ context.Context, req *msgdiscoverypb.GetMessagesSinceRequest) (*msgdiscoverypb.GetMessagesSinceResponse, error) {
	d.f.mu.Lock()
	defer d.f.mu.Unlock()
	resp := &msgdiscoverypb.GetMessagesSinceResponse{}
	for i, m := range d.f.messages {
		if seq := int64(i + 1); seq >= req.SinceSequence {
			resp.Results = append(resp.Results, &msgdiscoverypb.VerifierResultWithSequence{VerifierResult: m.committee, Sequence: seq})
		}
	}
	return resp, nil
}

type fakeCommittee struct {
	verifierpb.UnimplementedVerifierServer
	f *fakeVerifiers
}

// GetVerifierResultsForMessage returns one entry per ID; an unknown ID gets an empty result, as the aggregator does.
func (c *fakeCommittee) GetVerifierResultsForMessage(_ context.Context, req *verifierpb.GetVerifierResultsForMessageRequest) (*verifierpb.GetVerifierResultsForMessageResponse, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	resp := &verifierpb.GetVerifierResultsForMessageResponse{}
	for _, raw := range req.MessageIds {
		var id protocol.Bytes32
		copy(id[:], raw)
		if m, ok := c.f.byID[id]; ok {
			resp.Results = append(resp.Results, m.committee)
		} else {
			resp.Results = append(resp.Results, &verifierpb.VerifierResult{})
		}
	}
	return resp, nil
}
