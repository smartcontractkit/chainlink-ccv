package chainaccess

import (
	"context"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// CreateAccessorFactory is a factory that can construct accessors needed by the verifier service.
type CreateAccessorFactory[T any] func(
	ctx context.Context,
	lggr logger.Logger,
	infos Infos[T],
	onRampAddresses map[string]string,
	rmnRemoteAddresses map[string]string,
) (AccessorFactory, error)
