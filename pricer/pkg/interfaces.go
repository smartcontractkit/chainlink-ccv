package pricer

import (
	"context"

	ks "github.com/smartcontractkit/chainlink-ccv/pricer/pkg/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"
)

type Chain interface {
	// Start initializes all services necessary for interacting with the chain.
	Start(ctx context.Context) error
	// Tick performs a single tick of the chain.
	Tick(ctx context.Context) error
	// CreateKeystore creates a keystore for the chain.
	// TODO: This can likely be moved to a per-chain family interface.
	CreateKeystore(ctx context.Context, cfg ks.KMSConfig, keystoreData []byte, keystorePassword string) (core.Keystore, error)
	// Close closes all services necessary for interacting with the chain.
	Close() error
}
