package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
	iclient "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client/internal"
	mocksiclient "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestProcessResponse(t *testing.T) {
	cases := []struct {
		name                      string
		status                    int
		body                      []byte
		wantErr                   bool
		wantErrContains           string
		wantErrIsResponseTooLarge bool
		wantMessagesCount         int
	}{
		{
			name:              "success_200_json",
			status:            http.StatusOK,
			wantErr:           false,
			wantMessagesCount: 1,
			body: func() []byte {
				msg := common.MessageWithMetadata{Message: protocol.Message{}, Metadata: common.MessageMetadata{}}
				respObj := v1.MessagesResponse{Messages: map[string]common.MessageWithMetadata{"0x1": msg}, Success: true}
				b, _ := json.Marshal(respObj)
				return b
			}(),
		},
		{
			name:            "non_ok_status_includes_body",
			status:          http.StatusInternalServerError,
			body:            []byte("server error details"),
			wantErr:         true,
			wantErrContains: "indexer returned status",
		},
		{
			name:                      "oversized_body_returns_err",
			status:                    http.StatusOK,
			wantErr:                   true,
			wantErrIsResponseTooLarge: true,
			body: func() []byte {
				big := make([]byte, MaxBodySize+1)
				for i := range big {
					big[i] = 'a'
				}
				return big
			}(),
		},
		{
			name:            "malformed_json_returns_error",
			status:          http.StatusOK,
			body:            []byte("not-json"),
			wantErr:         true,
			wantErrContains: "failed to decode JSON response",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: tc.status, Body: io.NopCloser(bytes.NewReader(tc.body))}
			var out v1.MessagesResponse
			err := processResponse(resp, &out)
			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrIsResponseTooLarge {
					require.True(t, errors.Is(err, ErrResponseTooLarge), "expected ErrResponseTooLarge, got: %v", err)
					return
				}
				if tc.wantErrContains != "" {
					require.Contains(t, err.Error(), tc.wantErrContains)
				}
				return
			}

			// no error expected
			require.NoError(t, err)
			if tc.wantMessagesCount != 0 {
				require.Len(t, out.Messages, tc.wantMessagesCount)
				// If we expect one message verify the expected key exists and basic content
				if tc.wantMessagesCount == 1 {
					require.Contains(t, out.Messages, "0x1")
					msg := out.Messages["0x1"]
					// basic sanity checks on message structure
					require.NotNil(t, msg.Message)
				}
			}
		})
	}
}

func TestMaybeGetBody(t *testing.T) {
	// nil reader
	require.Error(t, func() error {
		_, err := maybeGetBody(nil, 10)
		return err
	}())

	// small body
	small := io.NopCloser(bytes.NewReader([]byte("hello")))
	b, err := maybeGetBody(small, 10)
	require.NoError(t, err)
	require.Equal(t, "hello", string(b))

	// oversized body
	big := make([]byte, MaxBodySize+1)
	for i := range big {
		big[i] = 'x'
	}
	_, err = maybeGetBody(io.NopCloser(bytes.NewReader(big)), MaxBodySize)
	require.True(t, errors.Is(err, ErrResponseTooLarge), "expected ErrResponseTooLarge, got: %v", err)
}

func TestParseVerifierResultsParams(t *testing.T) {
	cases := []struct {
		name string
		in   v1.VerifierResultsInput
		want *iclient.VerifierResultsParams
	}{
		{
			name: "empty",
			in:   v1.VerifierResultsInput{},
			want: &iclient.VerifierResultsParams{},
		},
		{
			name: "filled",
			in: v1.VerifierResultsInput{
				SourceChainSelectors: []protocol.ChainSelector{1, 2},
				DestChainSelectors:   []protocol.ChainSelector{3},
				Start:                100,
				End:                  200,
				Limit:                10,
				Offset:               5,
			},
			want: &iclient.VerifierResultsParams{
				SourceChainSelectors: &[]protocol.ChainSelector{1, 2},
				DestChainSelectors:   &[]protocol.ChainSelector{3},
				Start:                ptrInt64(100),
				End:                  ptrInt64(200),
				Limit:                ptrUint64(10),
				Offset:               ptrUint64(5),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseVerifierResultsParams(tc.in)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestParseMessagesParams(t *testing.T) {
	cases := []struct {
		name string
		in   v1.MessagesInput
		want *iclient.MessagesParams
	}{
		{
			name: "empty",
			in:   v1.MessagesInput{},
			want: &iclient.MessagesParams{},
		},
		{
			name: "filled",
			in: v1.MessagesInput{
				SourceChainSelectors: []protocol.ChainSelector{4},
				DestChainSelectors:   []protocol.ChainSelector{5, 6},
				Start:                1000,
				End:                  2000,
				Limit:                20,
				Offset:               2,
			},
			want: &iclient.MessagesParams{
				SourceChainSelectors: &[]protocol.ChainSelector{4},
				DestChainSelectors:   &[]protocol.ChainSelector{5, 6},
				Start:                ptrInt64(1000),
				End:                  ptrInt64(2000),
				Limit:                ptrUint64(20),
				Offset:               ptrUint64(2),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMessagesParams(tc.in)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestNewIndexerClientAndMethods(t *testing.T) {
	// prepare responses for methods
	msg := common.MessageWithMetadata{Message: protocol.Message{}, Metadata: common.MessageMetadata{}}
	messagesResp := v1.MessagesResponse{Messages: map[string]common.MessageWithMetadata{"0x1": msg}, Success: true}
	bmsg, _ := json.Marshal(messagesResp)

	vrResp := v1.VerifierResultsResponse{Success: true, VerifierResults: map[string][]common.VerifierResultWithMetadata{"m1": {{VerifierResult: protocol.VerifierResult{VerifierSourceAddress: protocol.UnknownAddress{0x01}}}}}}
	bvr, _ := json.Marshal(vrResp)

	midResp := v1.VerifierResultsByMessageIDResponse{Success: true, MessageID: protocol.Bytes32{}, Results: []common.VerifierResultWithMetadata{{VerifierResult: protocol.VerifierResult{VerifierSourceAddress: protocol.UnknownAddress{0x02}}}}}
	bmid, _ := json.Marshal(midResp)

	httpMessages := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(bmsg)), Header: http.Header{"Content-Type": []string{"application/json"}}}
	httpVR := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(bvr)), Header: http.Header{"Content-Type": []string{"application/json"}}}
	httpMid := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(bmid)), Header: http.Header{"Content-Type": []string{"application/json"}}}

	// create generated mock and set expectations
	mockCli := mocksiclient.NewMockClientInterface(t)
	// VerifierResults called with any context and params
	mockCli.EXPECT().VerifierResults(mock.Anything, mock.Anything).Return(httpVR, nil).Once()
	mockCli.EXPECT().Messages(mock.Anything, mock.Anything).Return(httpMessages, nil).Once()
	mockCli.EXPECT().VerifierResultsByMessageId(mock.Anything, "0x00").Return(httpMid, nil).Once()

	ic := &IndexerClient{client: mockCli, lggr: logger.Test(t), indexerURI: "http://example.com/"}

	t.Run("verifierresults", func(t *testing.T) {
		vrOut, err := ic.VerifierResults(context.Background(), v1.VerifierResultsInput{})
		require.NoError(t, err)
		require.Len(t, vrOut.VerifierResults, 1)
	})

	t.Run("messages", func(t *testing.T) {
		msgOut, err := ic.Messages(context.Background(), v1.MessagesInput{})
		require.NoError(t, err)
		require.Len(t, msgOut.Messages, 1)
		require.Contains(t, msgOut.Messages, "0x1")
	})

	t.Run("verifierresults_byid", func(t *testing.T) {
		midOut, err := ic.VerifierResultsByMessageID(context.Background(), v1.VerifierResultsByMessageIDInput{MessageID: "0x00"})
		require.NoError(t, err)
		require.Len(t, midOut.Results, 1)
		require.Equal(t, "0x02", midOut.Results[0].VerifierResult.VerifierSourceAddress.String())
	})
}

func TestClientMethods_ResponseProcessingErrors(t *testing.T) {
	// verifierresults: non-200 status -> expect error containing status
	t.Run("verifierresults_non200", func(t *testing.T) {
		httpResp := &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(bytes.NewReader([]byte("server error details"))), Header: http.Header{"Content-Type": []string{"application/json"}}}
		mockCli := mocksiclient.NewMockClientInterface(t)
		ic := &IndexerClient{client: mockCli, lggr: logger.Test(t), indexerURI: "http://example.com/"}
		mockCli.EXPECT().VerifierResults(mock.Anything, mock.Anything).Return(httpResp, nil).Once()
		err := func() error { _, e := ic.VerifierResults(context.Background(), v1.VerifierResultsInput{}); return e }()
		require.Error(t, err)
		require.Contains(t, err.Error(), "indexer returned status")
	})

	// messages: malformed JSON -> expect JSON decode error
	t.Run("messages_malformed_json", func(t *testing.T) {
		httpResp := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte("not-json"))), Header: http.Header{"Content-Type": []string{"application/json"}}}
		mockCli := mocksiclient.NewMockClientInterface(t)
		ic := &IndexerClient{client: mockCli, lggr: logger.Test(t), indexerURI: "http://example.com/"}
		mockCli.EXPECT().Messages(mock.Anything, mock.Anything).Return(httpResp, nil).Once()
		err := func() error { _, e := ic.Messages(context.Background(), v1.MessagesInput{}); return e }()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode JSON response")
	})

	// verifierresults by-id: oversized body -> expect ErrResponseTooLarge
	t.Run("byid_oversized", func(t *testing.T) {
		big := make([]byte, MaxBodySize+1)
		for i := range big {
			big[i] = 'x'
		}
		httpResp := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(big)), Header: http.Header{"Content-Type": []string{"application/json"}}}
		mockCli := mocksiclient.NewMockClientInterface(t)
		ic := &IndexerClient{client: mockCli, lggr: logger.Test(t), indexerURI: "http://example.com/"}
		mockCli.EXPECT().VerifierResultsByMessageId(mock.Anything, mock.Anything).Return(httpResp, nil).Once()
		err := func() error {
			_, e := ic.VerifierResultsByMessageID(context.Background(), v1.VerifierResultsByMessageIDInput{MessageID: "0x00"})
			return e
		}()
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrResponseTooLarge), "expected ErrResponseTooLarge, got: %v", err)
	})
}

func TestClientMethods_TransportErrors(t *testing.T) {
	cases := []struct {
		name   string
		method string
	}{
		{"verifier_err", "verifierresults"},
		{"messages_err", "messages"},
		{"byid_err", "byid"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mockCli := mocksiclient.NewMockClientInterface(t)
			ic := &IndexerClient{client: mockCli, lggr: logger.Test(t), indexerURI: "http://example.com/"}

			call := setupMockAndCall(mockCli, ic, tc.method, nil, errors.New("network"))
			require.Error(t, call())
		})
	}
}

// setupMockAndCall centralizes mock expectation setup and returns a function that
// executes the corresponding IndexerClient method and returns its error.
func setupMockAndCall(mockCli *mocksiclient.MockClientInterface, ic *IndexerClient, method string, resp *http.Response, respErr error) func() error {
	switch method {
	case "verifierresults":
		mockCli.EXPECT().VerifierResults(mock.Anything, mock.Anything).Return(resp, respErr).Once()
		return func() error {
			_, err := ic.VerifierResults(context.Background(), v1.VerifierResultsInput{})
			return err
		}
	case "messages":
		mockCli.EXPECT().Messages(mock.Anything, mock.Anything).Return(resp, respErr).Once()
		return func() error { _, err := ic.Messages(context.Background(), v1.MessagesInput{}); return err }
	case "byid":
		mockCli.EXPECT().VerifierResultsByMessageId(mock.Anything, mock.Anything).Return(resp, respErr).Once()
		return func() error {
			_, err := ic.VerifierResultsByMessageID(context.Background(), v1.VerifierResultsByMessageIDInput{MessageID: "0x00"})
			return err
		}
	default:
		return func() error { return errors.New("unknown method") }
	}
}

// helper ptr functions
func ptrInt64(v int64) *int64 { return &v }

func ptrUint64(v uint64) *uint64 { return &v }
