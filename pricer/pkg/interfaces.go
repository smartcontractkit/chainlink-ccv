package pricer

import (
	"context"

	ks "github.com/smartcontractkit/chainlink-ccv/pricer/pkg/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"
)

type Chain interface {
	Start(ctx context.Context) error
	Tick(ctx context.Context) error
	CreateKeystore(ctx context.Context, cfg ks.KMSConfig, keystoreData []byte, keystorePassword string) (core.Keystore, error)
	Close() error
}
