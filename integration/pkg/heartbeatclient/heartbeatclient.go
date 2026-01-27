package heartbeatclient

import (
	"context"
	"crypto/tls"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	insecuregrpc "google.golang.org/grpc/credentials/insecure"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	heartbeatpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/heartbeat/v1"
)

const (
	MinTLSVersion = tls.VersionTLS13
)

// HeartbeatClient provides methods to send heartbeats to the aggregator service.
type HeartbeatClient struct {
	client heartbeatpb.HeartbeatServiceClient
	conn   *grpc.ClientConn
	lggr   logger.Logger
}

// NewHeartbeatClient creates a new heartbeat client that communicates with the aggregator.
// If insecure is true, TLS verification is disabled (only for testing).
func NewHeartbeatClient(address string, lggr logger.Logger, hmacConfig *hmac.ClientConfig, insecure bool) (*HeartbeatClient, error) {
	var dialOptions []grpc.DialOption
	if insecure {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecuregrpc.NewCredentials()))
	} else {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: MinTLSVersion})))
	}

	if hmacConfig != nil {
		dialOptions = append(dialOptions, grpc.WithUnaryInterceptor(hmac.NewClientInterceptor(hmacConfig)))
	}

	conn, err := grpc.NewClient(
		address,
		dialOptions...,
	)
	if err != nil {
		return nil, err
	}

	lggr.Infof("Created HeartbeatClient connecting to %s", address)

	return &HeartbeatClient{
		client: heartbeatpb.NewHeartbeatServiceClient(conn),
		conn:   conn,
		lggr:   logger.With(lggr, "service", "heartbeat_client", "aggregatorAddress", address),
	}, nil
}

// SendHeartbeat sends a heartbeat request to the aggregator.
func (hc *HeartbeatClient) SendHeartbeat(ctx context.Context, req *heartbeatpb.HeartbeatRequest, opts ...grpc.CallOption) (*heartbeatpb.HeartbeatResponse, error) {
	resp, err := hc.client.SendHeartbeat(ctx, req, opts...)
	if err != nil {
		hc.lggr.Errorw("Failed to send heartbeat", "error", err)
		return nil, fmt.Errorf("failed to send heartbeat: %w", err)
	}
	hc.lggr.Debugw("Heartbeat sent successfully", "timestamp", req.SendTimestamp)
	return resp, nil
}

// Close closes the gRPC connection to the aggregator server.
func (hc *HeartbeatClient) Close() error {
	if hc.conn != nil {
		return hc.conn.Close()
	}
	return nil
}
