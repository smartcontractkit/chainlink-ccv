package storageaccess

import (
	"context"
	"crypto/tls"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"

	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

// ResultEntry is one message ID's slot in the aggregator's batch
// GetVerifierResultsForMessage response, decoded from protobuf so callers outside
// this package never import the chainlink protos (depguard forbids them in
// verifier/ and executor/ packages).
type ResultEntry struct {
	// Present is false when the response carried neither a result nor an error
	// entry for this index.
	Present bool
	// ErrorCode is the per-ID error entry's status code; codes.OK (0) when the
	// aggregator returned a result instead.
	ErrorCode int32
	// ErrorMsg is the per-ID error entry's message, if any.
	ErrorMsg string
	// CcvData is the result's ccv data; non-empty only when the aggregator holds
	// attested data for the message.
	CcvData []byte
}

// ResultsClient is the aggregator's unauthenticated verifier-results read API.
type ResultsClient interface {
	// GetVerifierResultsForMessage returns one ResultEntry per requested message ID,
	// index-aligned with messageIDs.
	GetVerifierResultsForMessage(ctx context.Context, messageIDs [][]byte) ([]ResultEntry, error)
	// Close releases the underlying connection.
	Close() error
}

// DialResultsClient opens the aggregator's unauthenticated read path: TLS transport
// credentials, no auth interceptor.
func DialResultsClient(address string) (ResultsClient, error) {
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to aggregator: %w", err)
	}
	return &aggregatorResultsClient{client: verifierpb.NewVerifierClient(conn), conn: conn}, nil
}

type aggregatorResultsClient struct {
	client verifierpb.VerifierClient
	conn   *grpc.ClientConn
}

func (c *aggregatorResultsClient) GetVerifierResultsForMessage(ctx context.Context, messageIDs [][]byte) ([]ResultEntry, error) {
	resp, err := c.client.GetVerifierResultsForMessage(ctx, &verifierpb.GetVerifierResultsForMessageRequest{MessageIds: messageIDs})
	if err != nil {
		return nil, err
	}
	entries := make([]ResultEntry, len(messageIDs))
	for i := range entries {
		entries[i] = resultEntryAt(resp, i)
	}
	return entries, nil
}

func (c *aggregatorResultsClient) Close() error { return c.conn.Close() }

// resultEntryAt decodes entry i of the batch response: a per-ID error status other
// than OK means "not found"; only a result with non-empty ccv data is an attestation.
func resultEntryAt(resp *verifierpb.GetVerifierResultsForMessageResponse, i int) ResultEntry {
	if i < len(resp.GetErrors()) {
		if st := resp.GetErrors()[i]; st != nil && st.GetCode() != int32(codes.OK) {
			return ResultEntry{Present: true, ErrorCode: st.GetCode(), ErrorMsg: st.GetMessage()}
		}
	}
	if i < len(resp.GetResults()) {
		return ResultEntry{Present: true, CcvData: resp.GetResults()[i].GetCcvData()}
	}
	return ResultEntry{}
}
