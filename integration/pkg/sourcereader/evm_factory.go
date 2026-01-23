package sourcereader

import (
	"context"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
)

type EVMFactory struct {
	lggr               logger.Logger
	helper             *blockchain.Helper
	onRampAddresses    map[string]string
	rmnRemoteAddresses map[string]string
	headTrackers       map[protocol.ChainSelector]heads.Tracker
	chainClients       map[protocol.ChainSelector]client.Client
}

func NewEVMFactory(
	lggr logger.Logger,
	helper *blockchain.Helper,
	onRampAddresses,
	rmnRemoteAddresses map[string]string,
	headTrackers map[protocol.ChainSelector]heads.Tracker,
	chainClients map[protocol.ChainSelector]client.Client,
) *EVMFactory {
	return &EVMFactory{
		lggr:               lggr,
		helper:             helper,
		onRampAddresses:    onRampAddresses,
		rmnRemoteAddresses: rmnRemoteAddresses,
		headTrackers:       headTrackers,
		chainClients:       chainClients,
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
	chainClient, ok := f.chainClients[chainSelector]
	if !ok {
		return nil, fmt.Errorf("chain client is not set for chain %d", chainSelector)
	}

	// Create head tracker wrapper
	headTracker, ok := f.headTrackers[chainSelector]
	if !ok {
		return nil, fmt.Errorf("head tracker is not set for chain %d", chainSelector)
	}

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
