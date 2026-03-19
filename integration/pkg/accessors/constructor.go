package accessors

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type CreateAccessorFactory func(
	ctx context.Context,
	lggr logger.Logger,
	// TODO: blockchain.Info needs to be more family agnostic.
	blockchainInfos map[string]*blockchain.Info,
	onRampAddresses map[string]string,
	rmnRemoteAddresses map[string]string,
) (chainaccess.AccessorFactory, error)
