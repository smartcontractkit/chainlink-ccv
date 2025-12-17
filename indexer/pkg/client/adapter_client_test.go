package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
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
