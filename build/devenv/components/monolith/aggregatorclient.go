package monolith

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

type AggregatorClient struct {
	logger               zerolog.Logger
	addr                 string
	verifierResultClient verifierpb.VerifierClient
	conn                 *grpc.ClientConn
}

// NewAggregatorClient creates a new AggregatorClient with TLS.
// If caCertFile is provided, it will be used to verify the server certificate.
func NewAggregatorClient(logger zerolog.Logger, addr, caCertFile string) (*AggregatorClient, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}

	if caCertFile != "" {
		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert file: %w", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append CA cert to pool")
		}
		tlsConfig.RootCAs = certPool
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to aggregator: %w", err)
	}

	return &AggregatorClient{
		logger:               logger,
		addr:                 addr,
		verifierResultClient: verifierpb.NewVerifierClient(conn),
		conn:                 conn,
	}, nil
}

func (a *AggregatorClient) Close() error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

func (a *AggregatorClient) WaitForVerifierResultForMessage(
	ctx context.Context,
	messageID [32]byte,
	tickInterval time.Duration,
) (*verifierpb.VerifierResult, error) {
	msgIDHex := common.BytesToHash(messageID[:]).Hex()
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
		case <-ticker.C:
			result, err := a.GetVerifierResultForMessage(ctx, messageID)
			if err != nil {
				a.logger.Error().Err(err).Msgf("failed to get verifier result for messageID: %s, retrying", msgIDHex)
				continue
			}
			if result != nil && len(result.CcvData) > 0 {
				a.logger.Info().
					Str("messageID", msgIDHex).
					Int("ccvDataLen", len(result.CcvData)).
					Msg("found verifier result for messageID in aggregator")
				return result, nil
			}
			a.logger.Error().Msgf("no verifier result found for messageID: %s, retrying", msgIDHex)
		}
	}
}

func (a *AggregatorClient) GetVerifierResultForMessage(ctx context.Context, messageID [32]byte) (*verifierpb.VerifierResult, error) {
	resp, err := a.verifierResultClient.GetVerifierResultsForMessage(ctx, &verifierpb.GetVerifierResultsForMessageRequest{
		MessageIds: [][]byte{messageID[:]},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get verifier result: %w", err)
	}

	// Check for errors in the batch response
	if len(resp.Errors) > 0 && resp.Errors[0].Code != 0 {
		return nil, fmt.Errorf("verifier result error: %s", resp.Errors[0].Message)
	}

	// Return the first (and only) result
	if len(resp.Results) > 0 {
		return resp.Results[0], nil
	}

	return nil, fmt.Errorf("no verifier result found")
}
