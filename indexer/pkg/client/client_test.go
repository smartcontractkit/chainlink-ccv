package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	iclient "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client/internal"
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
				msg := protocol.MessageWithMetadata{Message: protocol.Message{}, Metadata: protocol.MessageMetadata{}}
				respObj := protocol.MessagesV1Response{Messages: map[string]protocol.MessageWithMetadata{"0x1": msg}, Success: true}
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
			var out protocol.MessagesV1Response
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

func TestGetAddrs(t *testing.T) {
	results := []protocol.VerifierResult{
		{VerifierSourceAddress: protocol.UnknownAddress{0x01}},
		{VerifierSourceAddress: protocol.UnknownAddress{0x02}},
	}
	addrs := getAddrs(results)
	require.Len(t, addrs, 2)
	// verify exact contents and order
	require.Equal(t, "0x01", addrs[0])
	require.Equal(t, "0x02", addrs[1])
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

func TestReadMessages(t *testing.T) {
	msg := protocol.MessageWithMetadata{Message: protocol.Message{}, Metadata: protocol.MessageMetadata{}}
	messagesResp := protocol.MessagesV1Response{Messages: map[string]protocol.MessageWithMetadata{"0x1": msg}, Success: true}
	bmsg, _ := json.Marshal(messagesResp)

	mock := &mockClient{
		getMessagesResp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(bmsg))},
	}
	cw := &iclient.ClientWithResponses{ClientInterface: mock}
	ic := &IndexerClient{ClientWithResponses: cw, lggr: logger.Test(t)}

	msgs, err := ic.ReadMessages(context.Background(), protocol.MessagesV1Request{})
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	// verify the expected message key and value are present
	require.Contains(t, msgs, "0x1")
	actual := msgs["0x1"]
	// Check some deterministic fields rather than strict struct equality, to avoid
	// nil vs empty-slice differences for alias types like UnknownAddress.
	require.Len(t, actual.Message.Data, 0)
	require.Equal(t, protocol.SequenceNumber(0), actual.Message.SequenceNumber)
	require.True(t, actual.Metadata.IngestionTimestamp.IsZero())
}

func TestGetVerifierResults(t *testing.T) {
	midResp := protocol.MessageIDV1Response{Success: true, MessageID: protocol.Bytes32{}, Results: []protocol.VerifierResultWithMetadata{{VerifierResult: protocol.VerifierResult{VerifierSourceAddress: protocol.UnknownAddress{0x01}}}}}
	bmid, _ := json.Marshal(midResp)

	mock := &mockClient{
		messageByIdResp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(bmid))},
	}
	cw := &iclient.ClientWithResponses{ClientInterface: mock}
	ic := &IndexerClient{ClientWithResponses: cw, lggr: logger.Test(t)}

	vr, err := ic.GetVerifierResults(context.Background(), protocol.Bytes32{})
	require.NoError(t, err)
	require.Len(t, vr, 1)
	// verify the verifier source address is as expected
	require.Equal(t, "0x01", vr[0].VerifierSourceAddress.String())
}

func TestNewIndexerClient(t *testing.T) {
	ic, err := NewIndexerClient(logger.Test(t), "http://example.com/", nil)
	require.NoError(t, err)
	require.NotNil(t, ic)
	// ensure fields are set
	require.Equal(t, "http://example.com/", ic.indexerURI)
	require.NotNil(t, ic.ClientWithResponses)
}

// mockClient implements the internal ClientInterface used by ClientWithResponses.
type mockClient struct {
	getMessagesResp *http.Response
	messageByIdResp *http.Response
	getErr          error
	msgIdErr        error
}

func (m *mockClient) MessageById(ctx context.Context, messageID string, reqEditors ...iclient.RequestEditorFn) (*http.Response, error) {
	return m.messageByIdResp, m.msgIdErr
}

func (m *mockClient) GetMessages(ctx context.Context, params *iclient.GetMessagesParams, reqEditors ...iclient.RequestEditorFn) (*http.Response, error) {
	return m.getMessagesResp, m.getErr
}

func (m *mockClient) VerifierResult(ctx context.Context, params *iclient.VerifierResultParams, reqEditors ...iclient.RequestEditorFn) (*http.Response, error) {
	return nil, nil
}
