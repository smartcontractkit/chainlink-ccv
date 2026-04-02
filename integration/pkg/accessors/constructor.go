package accessors

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type CreateAccessorFactory[T any] func(
	ctx context.Context,
	lggr logger.Logger,
	infos Infos[T],
	onRampAddresses map[string]string,
	rmnRemoteAddresses map[string]string,
) (chainaccess.AccessorFactory, error)
