// Package jdclient provides a client for connecting to the Job Distributor.
package jdclient

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"sync"

	"github.com/smartcontractkit/wsrpc"
	wsrpcLogger "github.com/smartcontractkit/wsrpc/logger"

	pb "github.com/smartcontractkit/chainlink-protos/orchestrator/feedsmanager"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// JobProposal represents a job proposal received from the Job Distributor.
type JobProposal struct {
	ID      string
	Version int64
	Spec    string
}

// Client is a WSRPC client for connecting to the Job Distributor.
type Client struct {
	csaSigner   crypto.Signer
	jdPublicKey ed25519.PublicKey
	jdURL       string
	lggr        logger.Logger

	mu             sync.Mutex
	conn           *wsrpc.ClientConn
	feedsManager   pb.FeedsManagerClient
	handlers       *Handlers
	jobProposalCh  chan *JobProposal
	closeCh        chan struct{}
	closeOnce      sync.Once
}

// NewClient creates a new JD client.
// The csaSigner is a crypto.Signer that implements Ed25519 signing (e.g., from a keystore).
// The jdPublicKey is the Job Distributor's Ed25519 public key for mTLS authentication.
func NewClient(csaSigner crypto.Signer, jdPublicKey ed25519.PublicKey, jdURL string, lggr logger.Logger) *Client {
	return &Client{
		csaSigner:     csaSigner,
		jdPublicKey:   jdPublicKey,
		jdURL:         jdURL,
		lggr:          lggr,
		jobProposalCh: make(chan *JobProposal, 10),
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
		wsrpc.WithLogger(wsrpcLogger.Nop()),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to JD: %w", err)
	}

	c.conn = conn
	c.feedsManager = pb.NewFeedsManagerClient(conn)
	c.handlers = NewHandlers(c.jobProposalCh, c.lggr)

	// Register the node service server to receive job proposals
	pb.RegisterNodeServiceServer(conn, c.handlers)

	c.lggr.Infow("Connected to Job Distributor")
	return nil
}

// JobProposalCh returns the channel on which job proposals are received.
func (c *Client) JobProposalCh() <-chan *JobProposal {
	return c.jobProposalCh
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
