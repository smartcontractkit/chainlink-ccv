package canton

import (
	"context"
	"fmt"
	"strconv"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader/canton"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type factory struct {
	lggr   logger.Logger
	helper *blockchain.Helper

	// map of chain selector to canton reader config
	// this is used to create the canton source reader
	config map[string]canton.ReaderConfig
}

// GetAccessor implements chainaccess.AccessorFactory.
func (f *factory) GetAccessor(ctx context.Context, chainSelector protocol.ChainSelector) (chainaccess.Accessor, error) {
	if f.config == nil {
		return nil, fmt.Errorf("canton config is not set - can't get accessor for chain %d", chainSelector)
	}

	family, err := chainsel.GetSelectorFamily(uint64(chainSelector))
	if err != nil {
		return nil, fmt.Errorf("failed to get selector family for %d - update chain-selectors library?: %w", chainSelector, err)
	}
	if family != chainsel.FamilyCanton {
		return nil, fmt.Errorf("skipping chain, only canton is supported for chain %d, family %s", chainSelector, family)
	}

	strSelector := strconv.FormatUint(uint64(chainSelector), 10)
	cantonConfig, ok := f.config[strSelector]
	if !ok {
		return nil, fmt.Errorf("canton config not found for chain %d", chainSelector)
	}

	netData, err := f.helper.GetNetworkSpecificData(chainSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to get network specific data for chain %d: %w", chainSelector, err)
	}
	if netData == nil || netData.CantonEndpoints == nil {
		return nil, fmt.Errorf("canton endpoints not found for chain %d", chainSelector)
	}

	sourceReader, err := canton.NewSourceReader(
		netData.CantonEndpoints.GRPCLedgerAPIURL,
		netData.CantonEndpoints.JWT,
		canton.ReaderConfig{
			CCIPOwnerParty:            cantonConfig.CCIPOwnerParty,
			CCIPMessageSentTemplateID: cantonConfig.CCIPMessageSentTemplateID,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create source reader: %w", err)
	}

	return newAccessor(sourceReader), nil
}

func NewFactory(lggr logger.Logger, helper *blockchain.Helper, config map[string]canton.ReaderConfig) chainaccess.AccessorFactory {
	return &factory{
		lggr:   lggr,
		helper: helper,
		config: config,
	}
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
