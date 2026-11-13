package chainaccess

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// ChainEndpoint is a sanitized RPC endpoint. URLs must not contain credentials, query strings, or paths.
type ChainEndpoint struct {
	Name         string
	HTTPURL      string
	WSURL        string
	HasWebSocket bool
	Order        *int32
}

// ChainAttribute is one effective configuration value and where that value came from.
type ChainAttribute struct {
	Name   string
	Value  string
	Source string
}

// ChainInspection is a chain-family-neutral view of effective configuration and diagnostics.
type ChainInspection struct {
	Selector    protocol.ChainSelector
	Family      string
	ChainID     string
	Roles       []string
	Endpoints   []ChainEndpoint
	Attributes  []ChainAttribute
	Diagnostics []string
}

// ChainInspector is an optional accessor capability for sanitized effective-configuration display.
type ChainInspector interface {
	// InspectChain returns the current effective view without exposing raw secret configuration.
	InspectChain(ctx context.Context) (ChainInspection, error)
}
