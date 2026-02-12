// Package client provides a client for connecting to the Job Distributor.
// See Job Distributor docs for detailed information about the protocol: https://docs.jd.cldev.sh/.
// The role of the JD client is to handle requests from JD.
// For example, when someone proposes a job via JD, the JD client will receive the proposal and
// call the appropriate handler for that request.
package client

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"sync"

	"github.com/smartcontractkit/wsrpc"
	wsrpclogger "github.com/smartcontractkit/wsrpc/logger"

	pb "github.com/smartcontractkit/chainlink-protos/orchestrator/feedsmanager"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// ClientInterface defines the interface for interacting with the Job Distributor.
// This interface is implemented by *Client.
//
//revive:disable-next-line:exported
type ClientInterface interface {
	// Connect establishes a connection to the Job Distributor.
	Connect(ctx context.Context) error
	// Close closes the connection to the Job Distributor.
	Close() error
	// ApproveJob sends a job approval to the Job Distributor.
	ApproveJob(ctx context.Context, id string, version int64) error
	// JobProposalCh returns the channel on which job proposals are received.
	JobProposalCh() <-chan *pb.ProposeJobRequest
	// DeleteJobCh returns the channel on which job deletion requests are received.
	DeleteJobCh() <-chan *pb.DeleteJobRequest
	// RevokeJobCh returns the channel on which job revocation requests are received.
	RevokeJobCh() <-chan *pb.RevokeJobRequest
}

// Ensure Client implements ClientInterface.
var _ ClientInterface = (*Client)(nil)

// Client is a WSRPC client for connecting to the Job Distributor.
type Client struct {
	csaSigner   crypto.Signer
	jdPublicKey ed25519.PublicKey
	jdURL       string
	lggr        logger.Logger

	mu            sync.Mutex
	conn          *wsrpc.ClientConn
	feedsManager  pb.FeedsManagerClient
	handlers      *handlers
	jobProposalCh chan *pb.ProposeJobRequest
	deleteJobCh   chan *pb.DeleteJobRequest
	revokeJobCh   chan *pb.RevokeJobRequest
	closeCh       chan struct{}
	closeOnce     sync.Once
}

// New creates a new JD client.
// The csaSigner is a crypto.Signer that implements Ed25519 signing (e.g., from a keystore).
// The jdPublicKey is the Job Distributor's Ed25519 public key for mTLS authentication.
func New(csaSigner crypto.Signer, jdPublicKey ed25519.PublicKey, jdURL string, lggr logger.Logger) *Client {
	return &Client{
		csaSigner:     csaSigner,
		jdPublicKey:   jdPublicKey,
		jdURL:         jdURL,
		lggr:          lggr,
		jobProposalCh: make(chan *pb.ProposeJobRequest, 10),
		deleteJobCh:   make(chan *pb.DeleteJobRequest, 10),
		revokeJobCh:   make(chan *pb.RevokeJobRequest, 10),
		closeCh:       make(chan struct{}),
	}
}

// Connect establishes a connection to the Job Distributor.
// This is a blocking call that waits until the connection is established.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lggr.Infow("Connecting to Job Distributor", "url", c.jdURL)

	conn, err := wsrpc.DialWithContext(ctx, c.jdURL,
		wsrpc.WithTransportSigner(c.csaSigner, c.jdPublicKey),
		wsrpc.WithBlock(),
		wsrpc.WithLogger(wsrpclogger.Nop()),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to JD: %w", err)
	}

	c.conn = conn
	c.feedsManager = pb.NewFeedsManagerClient(conn)
	c.handlers = newHandlers(c.jobProposalCh, c.deleteJobCh, c.revokeJobCh, c.lggr)

	// Register the node service server to receive job proposals
	pb.RegisterNodeServiceServer(conn, c.handlers)

	c.lggr.Infow("Connected to Job Distributor")
	return nil
}

// JobProposalCh returns the channel on which job proposals are received.
func (c *Client) JobProposalCh() <-chan *pb.ProposeJobRequest {
	return c.jobProposalCh
}

// DeleteJobCh returns the channel on which job deletion requests are received.
func (c *Client) DeleteJobCh() <-chan *pb.DeleteJobRequest {
	return c.deleteJobCh
}

// RevokeJobCh returns the channel on which job revocation requests are received.
func (c *Client) RevokeJobCh() <-chan *pb.RevokeJobRequest {
	return c.revokeJobCh
}

// ApproveJob sends a job approval to the Job Distributor.
func (c *Client) ApproveJob(ctx context.Context, id string, version int64) error {
	c.mu.Lock()
	fm := c.feedsManager
	c.mu.Unlock()

	if fm == nil {
		return fmt.Errorf("not connected to JD")
	}

	c.lggr.Infow("Approving job", "id", id, "version", version)

	_, err := fm.ApprovedJob(ctx, &pb.ApprovedJobRequest{
		Uuid:    id,
		Version: version,
	})
	if err != nil {
		return fmt.Errorf("failed to approve job: %w", err)
	}

	c.lggr.Infow("Job approved", "id", id)
	return nil
}

// RejectJob sends a job rejection to the Job Distributor.
func (c *Client) RejectJob(ctx context.Context, id string, version int64) error {
	c.mu.Lock()
	fm := c.feedsManager
	c.mu.Unlock()

	if fm == nil {
		return fmt.Errorf("not connected to JD")
	}

	c.lggr.Infow("Rejecting job", "id", id, "version", version)

	_, err := fm.RejectedJob(ctx, &pb.RejectedJobRequest{
		Uuid:    id,
		Version: version,
	})
	if err != nil {
		return fmt.Errorf("failed to reject job: %w", err)
	}

	c.lggr.Infow("Job rejected", "id", id)
	return nil
}

// CancelJob sends a job cancellation to the Job Distributor.
func (c *Client) CancelJob(ctx context.Context, id string, version int64) error {
	c.mu.Lock()
	fm := c.feedsManager
	c.mu.Unlock()

	if fm == nil {
		return fmt.Errorf("not connected to JD")
	}

	c.lggr.Infow("Cancelling job", "id", id, "version", version)

	_, err := fm.CancelledJob(ctx, &pb.CancelledJobRequest{
		Uuid:    id,
		Version: version,
	})
	if err != nil {
		return fmt.Errorf("failed to cancel job: %w", err)
	}

	c.lggr.Infow("Job cancelled", "id", id)
	return nil
}

// Close closes the connection to the Job Distributor.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closeCh)

		c.mu.Lock()
		defer c.mu.Unlock()

		if c.conn != nil {
			c.lggr.Infow("Closing JD connection")
			err = c.conn.Close()
			c.conn = nil
		}
	})
	return err
}

// IsConnected returns true if the client is connected to the Job Distributor.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}
