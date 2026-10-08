package admin

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
)

// fakeResultsClient serves canned per-index entries: the protobuf translation is
// tested in storageaccess; these tests cover the console's interpretation.
type fakeResultsClient struct {
	entries []storageaccess.ResultEntry
	callErr error
}

func (f *fakeResultsClient) GetVerifierResultsForMessage(_ context.Context, _ [][]byte) ([]storageaccess.ResultEntry, error) {
	if f.callErr != nil {
		return nil, f.callErr
	}
	return f.entries, nil
}

func (f *fakeResultsClient) Close() error { return nil }

// notFoundClient answers "not found" for every requested ID, like an aggregator that
// holds none of the messages.
type notFoundClient struct{}

func (notFoundClient) GetVerifierResultsForMessage(_ context.Context, messageIDs [][]byte) ([]storageaccess.ResultEntry, error) {
	entries := make([]storageaccess.ResultEntry, len(messageIDs))
	for i := range entries {
		entries[i] = storageaccess.ResultEntry{Present: true, ErrorCode: int32(codes.NotFound), ErrorMsg: "message ID not found"}
	}
	return entries, nil
}

func (notFoundClient) Close() error { return nil }

func notFoundResultsClient() notFoundClient { return notFoundClient{} }

// installFakeResultsClient points the aggregator dial seam at a canned client.
func installFakeResultsClient(t *testing.T, client storageaccess.ResultsClient) {
	t.Helper()
	orig := dialVerifierClient
	dialVerifierClient = func(string) (storageaccess.ResultsClient, error) { return client, nil }
	t.Cleanup(func() { dialVerifierClient = orig })
}

// installDialError points the aggregator dial seam at a failing dial.
func installDialError(t *testing.T, err error) {
	t.Helper()
	orig := dialVerifierClient
	dialVerifierClient = func(string) (storageaccess.ResultsClient, error) { return nil, err }
	t.Cleanup(func() { dialVerifierClient = orig })
}

func TestAggregatorAttested(t *testing.T) {
	installFakeResultsClient(t, &fakeResultsClient{entries: []storageaccess.ResultEntry{
		{Present: true, CcvData: []byte{0xde, 0xad}},
	}})

	id := rescheduleMsgID(1)
	results := checkAttestations(context.Background(), "agg:443", [][]byte{id}, dialVerifierClient)
	require.Len(t, results, 1)
	require.Equal(t, AttestationAttested, results[0].State)
	require.Contains(t, results[0].Detail, "aggregator")
}

func TestAggregatorPerIDErrorMeansNotFound(t *testing.T) {
	installFakeResultsClient(t, &fakeResultsClient{entries: []storageaccess.ResultEntry{
		{Present: true, ErrorCode: int32(codes.NotFound), ErrorMsg: "message ID not found"},
	}})

	results := checkAttestations(context.Background(), "agg:443", [][]byte{rescheduleMsgID(2)}, dialVerifierClient)
	require.Equal(t, AttestationNotFound, results[0].State)
	require.Contains(t, results[0].Detail, "message ID not found")
}

// A per-ID Internal error (a mapping or config failure) is not proof of
// absence: only NotFound is. The state stays unknown, so execution remains
// disabled rather than allowing a replay.
func TestAggregatorPerIDInternalErrorIsUnknown(t *testing.T) {
	installFakeResultsClient(t, &fakeResultsClient{entries: []storageaccess.ResultEntry{
		{Present: true, ErrorCode: int32(codes.Internal), ErrorMsg: "dest chain not mapped"},
	}})

	results := checkAttestations(context.Background(), "agg:443", [][]byte{rescheduleMsgID(7)}, dialVerifierClient)
	require.Equal(t, AttestationUnknown, results[0].State)
	require.Contains(t, results[0].Detail, "Internal")
	require.Contains(t, results[0].Detail, "dest chain not mapped")
}

func TestAggregatorEmptyCcvDataMeansNotFound(t *testing.T) {
	installFakeResultsClient(t, &fakeResultsClient{entries: []storageaccess.ResultEntry{
		{Present: true, CcvData: []byte{}},
	}})

	results := checkAttestations(context.Background(), "agg:443", [][]byte{rescheduleMsgID(3)}, dialVerifierClient)
	require.Equal(t, AttestationNotFound, results[0].State)
}

func TestAggregatorCallErrorIsUnknown(t *testing.T) {
	installFakeResultsClient(t, &fakeResultsClient{callErr: context.DeadlineExceeded})

	results := checkAttestations(context.Background(), "agg:443", [][]byte{rescheduleMsgID(4)}, dialVerifierClient)
	require.Equal(t, AttestationUnknown, results[0].State)
	require.Contains(t, results[0].Detail, "aggregator unreachable")
}

func TestAggregatorDialErrorIsUnknown(t *testing.T) {
	installDialError(t, errors.New("connection refused"))

	results := checkAttestations(context.Background(), "agg:443", [][]byte{rescheduleMsgID(4)}, dialVerifierClient)
	require.Equal(t, AttestationUnknown, results[0].State)
	require.Equal(t, "connection refused", results[0].Detail)
}

func TestAggregatorMissingEntryIsUnknown(t *testing.T) {
	installFakeResultsClient(t, &fakeResultsClient{entries: []storageaccess.ResultEntry{}})

	results := checkAttestations(context.Background(), "agg:443", [][]byte{rescheduleMsgID(5)}, dialVerifierClient)
	require.Equal(t, AttestationUnknown, results[0].State)
	require.Contains(t, results[0].Detail, "missing an entry")
}

func TestAttestationNotConfiguredIsUnknown(t *testing.T) {
	results := checkAttestations(context.Background(), "", [][]byte{rescheduleMsgID(9)}, nil)
	require.Len(t, results, 1)
	require.Equal(t, AttestationUnknown, results[0].State)
	require.Contains(t, results[0].Detail, "not configured")
}
