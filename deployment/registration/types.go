package registration

import (
	"context"
	"time"

	"google.golang.org/grpc"

	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
)

// JDClient is the JD API surface needed for node registration and connection checks.
type JDClient interface {
	// GetNode retrieves a node by ID or CSA public key.
	GetNode(ctx context.Context, in *nodev1.GetNodeRequest, opts ...grpc.CallOption) (*nodev1.GetNodeResponse, error)
	// ListNodes returns nodes matching the request filter.
	ListNodes(ctx context.Context, in *nodev1.ListNodesRequest, opts ...grpc.CallOption) (*nodev1.ListNodesResponse, error)
	// RegisterNode creates a JD node record.
	RegisterNode(ctx context.Context, in *nodev1.RegisterNodeRequest, opts ...grpc.CallOption) (*nodev1.RegisterNodeResponse, error)
	// UpdateNode updates a JD node record.
	UpdateNode(ctx context.Context, in *nodev1.UpdateNodeRequest, opts ...grpc.CallOption) (*nodev1.UpdateNodeResponse, error)
}

// NodeSpec describes a chain-agnostic JD node identity.
type NodeSpec struct {
	Name        string
	Product     string
	Environment string
	IsBootstrap bool
	Labels      map[string]string
}

// Status reports whether registration created the JD record.
type Status string

const (
	StatusRegistered Status = "registered"
	StatusExisting   Status = "existing"
)

// Result describes the JD record after reconciliation.
type Result struct {
	NodeID           string
	Status           Status
	LabelsReconciled bool
}

const (
	DefaultConnectionTimeout = 3 * time.Minute
	DefaultPollInterval      = 2 * time.Second
)

// WaitConfig controls JD connection polling. Zero values select production defaults.
type WaitConfig struct {
	Timeout      time.Duration
	PollInterval time.Duration
}

func (c WaitConfig) withDefaults() WaitConfig {
	if c.Timeout <= 0 {
		c.Timeout = DefaultConnectionTimeout
	}
	if c.PollInterval <= 0 {
		c.PollInterval = DefaultPollInterval
	}
	return c
}
