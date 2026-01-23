package sourcereader

import (
	"context"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type EVMFactory struct {
	lggr               logger.Logger
	helper             *blockchain.Helper
	onRampAddresses    map[string]string
	rmnRemoteAddresses map[string]string
}

func NewEVMFactory(lggr logger.Logger, helper *blockchain.Helper, onRampAddresses, rmnRemoteAddresses map[string]string) *EVMFactory {
	return &EVMFactory{
		lggr:               lggr,
		helper:             helper,
		onRampAddresses:    onRampAddresses,
		rmnRemoteAddresses: rmnRemoteAddresses,
	}
}

func (f *EVMFactory) GetSourceReader(ctx context.Context, chainSelector protocol.ChainSelector) (chainaccess.SourceReader, error) {
	strSelector := strconv.FormatUint(uint64(chainSelector), 10)

	if f.onRampAddresses[strSelector] == "" {
		return nil, fmt.Errorf("on ramp address is not set for chain %d", chainSelector)
	}
	if f.rmnRemoteAddresses[strSelector] == "" {
		return nil, fmt.Errorf("RMN Remote address is not set for chain %d", chainSelector)
	}

	// Create chain client
	chainClient := pkg.CreateHealthyMultiNodeClient(ctx, f.helper, f.lggr, chainSelector)
	if chainClient == nil {
		return nil, fmt.Errorf("failed to create chain client for chain %d", chainSelector)
	}

	// Create head tracker wrapper
	headTracker := NewSimpleHeadTrackerWrapper(chainClient, f.lggr)

	evmSourceReader, err := NewEVMSourceReader(
		chainClient,
		headTracker,
		common.HexToAddress(f.onRampAddresses[strSelector]),
		common.HexToAddress(f.rmnRemoteAddresses[strSelector]),
		onramp.OnRampCCIPMessageSent{}.Topic().Hex(),
		chainSelector,
		f.lggr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create EVM source reader: %w", err)
	}

	f.lggr.Infow("Created EVM source reader", "chain", chainSelector)
	return evmSourceReader, nil
}
