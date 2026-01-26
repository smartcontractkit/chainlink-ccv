package evm

import (
	"context"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
)

type factory struct {
	lggr               logger.Logger
	helper             *blockchain.Helper
	onRampAddresses    map[string]string
	rmnRemoteAddresses map[string]string
	headTrackers       map[protocol.ChainSelector]heads.Tracker
	chainClients       map[protocol.ChainSelector]client.Client
}

// NewFactory creates a new EVM AccessorFactory.
// Head trackers and chain clients are injectable because different execution contexts may use different
// constructions / implementations of these objects.
func NewFactory(
	lggr logger.Logger,
	helper *blockchain.Helper,
	onRampAddresses, rmnRemoteAddresses map[string]string,
	headTrackers map[protocol.ChainSelector]heads.Tracker,
	chainClients map[protocol.ChainSelector]client.Client,
) chainaccess.AccessorFactory {
	return &factory{
		lggr:               lggr,
		helper:             helper,
		onRampAddresses:    onRampAddresses,
		rmnRemoteAddresses: rmnRemoteAddresses,
		headTrackers:       headTrackers,
		chainClients:       chainClients,
	}
}

func (f *factory) GetAccessor(ctx context.Context, chainSelector protocol.ChainSelector) (chainaccess.Accessor, error) {
	if f.onRampAddresses == nil || f.rmnRemoteAddresses == nil || f.chainClients == nil || f.headTrackers == nil {
		return nil, fmt.Errorf("evm accessor factory is not fully initialized - can't get accessor for chain %d", chainSelector)
	}

	family, err := chainsel.GetSelectorFamily(uint64(chainSelector))
	if err != nil {
		return nil, fmt.Errorf("failed to get selector family for %d - update chain-selectors library?: %w", chainSelector, err)
	}
	if family != chainsel.FamilyEVM {
		return nil, fmt.Errorf("skipping chain, only evm is supported for chain %d, family %s", chainSelector, family)
	}

	strSelector := strconv.FormatUint(uint64(chainSelector), 10)

	if f.onRampAddresses[strSelector] == "" {
		return nil, fmt.Errorf("on ramp address is not set for chain %d", chainSelector)
	}
	if f.rmnRemoteAddresses[strSelector] == "" {
		return nil, fmt.Errorf("RMN Remote address is not set for chain %d", chainSelector)
	}

	chainClient, ok := f.chainClients[chainSelector]
	if !ok {
		return nil, fmt.Errorf("chain client is not set for chain %d", chainSelector)
	}

	headTracker, ok := f.headTrackers[chainSelector]
	if !ok {
		return nil, fmt.Errorf("head tracker is not set for chain %d", chainSelector)
	}

	evmSourceReader, err := sourcereader.NewEVMSourceReader(
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

	return newAccessor(evmSourceReader), nil
}

type accessor struct {
	sourceReader chainaccess.SourceReader
}

func newAccessor(sourceReader chainaccess.SourceReader) chainaccess.Accessor {
	return &accessor{
		sourceReader: sourceReader,
	}
}

func (a *accessor) SourceReader() chainaccess.SourceReader {
	return a.sourceReader
}
