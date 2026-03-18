package verifier

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type CreateAccessorFactor func(
	ctx context.Context,
	lggr logger.Logger,
	blockchainInfos map[string]*blockchain.Info,
	cfg commit.Config,
	OnRampAddresses map[string]string,
	RMNRemoteAddresses map[string]string,
) (chainaccess.AccessorFactory, error)
