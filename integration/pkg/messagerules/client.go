package messagerules

import (
	"context"
	"crypto/tls"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	insecuregrpc "google.golang.org/grpc/credentials/insecure"

	shared "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	messagepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-rules/v1"
)

const MinTLSVersion = tls.VersionTLS12

type Client interface {
	ListMessageRules(ctx context.Context) ([]shared.Rule, error)
	Close() error
}

type GRPCClient struct {
	client messagepb.MessageRulesClient
	conn   *grpc.ClientConn
	lggr   logger.Logger
}

func NewGRPCClient(address string, lggr logger.Logger, hmacConfig *hmac.ClientConfig, insecure bool, maxRecvMsgSizeBytes int) (*GRPCClient, error) {
	dialOptions := buildDialOptions(hmacConfig, insecure, maxRecvMsgSizeBytes)
	conn, err := grpc.NewClient(address, dialOptions...)
	if err != nil {
		return nil, err
	}

	return &GRPCClient{
		client: messagepb.NewMessageRulesClient(conn),
		conn:   conn,
		lggr:   logger.With(lggr, "service", "message_rules_client", "aggregatorAddress", address),
	}, nil
}

func (c *GRPCClient) ListMessageRules(ctx context.Context) ([]shared.Rule, error) {
	resp, err := c.client.ListMessageRules(ctx, &messagepb.ListMessageRulesRequest{})
	if err != nil {
		c.lggr.Errorw("Failed to list message rules", "error", err)
		return nil, fmt.Errorf("failed to list message rules: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("message rules response is nil")
	}

	rules, err := shared.RulesFromProto(resp.GetRules())
	if err != nil {
		return nil, fmt.Errorf("failed to decode message rules: %w", err)
	}
	return rules, nil
}

func (c *GRPCClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func buildDialOptions(hmacConfig *hmac.ClientConfig, insecure bool, maxRecvMsgSizeBytes int) []grpc.DialOption {
	var opts []grpc.DialOption
	if insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecuregrpc.NewCredentials()))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: MinTLSVersion})))
	}

	if hmacConfig != nil {
		opts = append(opts, grpc.WithUnaryInterceptor(hmac.NewClientInterceptor(hmacConfig)))
	}

	if maxRecvMsgSizeBytes > 0 {
		opts = append(opts, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxRecvMsgSizeBytes)))
	}

	return opts
}
